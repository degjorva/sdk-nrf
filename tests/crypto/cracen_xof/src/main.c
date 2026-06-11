/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * cracen_xof - validation tests for the internal CRACEN streaming
 * SHAKE-128 / SHAKE-256 XOF API (sx_xof_*).
 *
 * The tests are organized in three layers, in increasing depth:
 *
 *   1. KAT layer (cracen_xof_kats):
 *      Compare short SHAKE outputs against published FIPS 202 reference
 *      values. This catches the cases where the BA418 mode bits are wrong
 *      or where SHAKE-128 is not implemented at all - a HW failure or
 *      a wrong-output failure here is decisive.
 *
 *   2. Streaming layer (cracen_xof_streaming):
 *      Cross-validate the "absorb-once, squeeze-many" pattern by
 *      comparing one-shot squeezes against split squeezes of the same
 *      total length. This is the load-bearing test for the
 *      save_state/resume_state-during-squeeze HW behavior.
 *
 *   3. Robustness layer (cracen_xof_robustness):
 *      Multi-chunk absorb, ctx reuse, and BA418-vs-BA413 concurrency.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <string.h>

#include <sxsymcrypt/xof.h>
#include <sxsymcrypt/hashdefs.h>
#include <cracen/statuscodes.h>

#include "kat_vectors.h"

LOG_MODULE_REGISTER(cracen_xof_test, LOG_LEVEL_INF);

/* SHAKE rates - duplicated here to keep the test independent from the
 * driver's internal naming if it ever changes.
 */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

/* Generate a deterministic test message.
 *
 * Used in tests where we don't have a reference vector but want a
 * non-empty, non-trivial message. Filling pattern is `i & 0xff`.
 */
static void make_test_message(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (uint8_t)(i & 0xff);
	}
}

/* ----------------------------------------------------------------- */
/* Test fixture: psa_crypto_init() once per suite.                    */
/* ----------------------------------------------------------------- */

static void *cracen_xof_setup(void)
{
	psa_status_t ps = psa_crypto_init();

	zassert_true(ps == PSA_SUCCESS || ps == PSA_ERROR_ALREADY_EXISTS,
		     "psa_crypto_init failed: %d", (int)ps);
	return NULL;
}

/* ================================================================= */
/* KAT layer                                                         */
/* ================================================================= */

ZTEST_SUITE(cracen_xof_kats, NULL, cracen_xof_setup, NULL, NULL, NULL);

/* Skip helper - all SHAKE-128 tests call this first so that we can iterate
 * on the SHAKE-256-only path independently from the SHAKE-128 mode-bit
 * search by setting CONFIG_TEST_CRACEN_XOF_SHAKE128=n.
 */
#define SKIP_IF_NO_SHAKE128() do { \
	if (!IS_ENABLED(CONFIG_TEST_CRACEN_XOF_SHAKE128)) { \
		ztest_test_skip(); \
	} \
} while (0)

/* shake128_kat_short - SHAKE-128("") first 32 bytes match FIPS 202.
 *
 * This is the single most important test in the suite: failure here
 * tells us the SHAKE-128 mode value (sha3_internal.h:SHA3_MODE_SHAKE128)
 * is wrong or that the BA418 does not implement SHAKE-128. Either way,
 * the documented mitigation is a SW SHAKE-128 fallback in cracen_sw/ext.
 */
ZTEST(cracen_xof_kats, test_shake128_empty_short)
{
	struct sx_xof ctx;
	uint8_t out[32];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, "sx_xof_init: %d", status);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, "sx_xof_finalize: %d", status);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, "sx_xof_squeeze: %d", status);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake128_empty_64, sizeof(out),
			  "SHAKE-128(empty) first 32 bytes mismatch");
}

ZTEST(cracen_xof_kats, test_shake256_empty_short)
{
	struct sx_xof ctx;
	uint8_t out[32];
	int status;

	status = sx_xof_init(&ctx, &sxhashalg_shake256);
	zassert_equal(status, SX_OK, "sx_xof_init: %d", status);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, "sx_xof_finalize: %d", status);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, "sx_xof_squeeze: %d", status);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake256_empty_64, sizeof(out),
			  "SHAKE-256(empty) first 32 bytes mismatch");
}

/* shake_kat_long - SHAKE("") first 64 bytes. Cross-checks that the second
 * rate-block's worth of squeeze output is also right. With the rate-block
 * boundary at 168 (SHAKE-128) / 136 (SHAKE-256), 64 bytes still fits in
 * the first squeeze, but the next test verifies the cross-block case.
 */
ZTEST(cracen_xof_kats, test_shake128_empty_long)
{
	struct sx_xof ctx;
	uint8_t out[64];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake128_empty_64, sizeof(out), NULL);
}

ZTEST(cracen_xof_kats, test_shake256_empty_long)
{
	struct sx_xof ctx;
	uint8_t out[64];
	int status;

	status = sx_xof_init(&ctx, &sxhashalg_shake256);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake256_empty_64, sizeof(out), NULL);
}

/* SHAKE-128("abc") - exercises the absorb path with a non-empty input.
 * "abc" is well below one rate block, so this also indirectly checks that
 * the SHAKE pad is applied to a partial block correctly.
 */
ZTEST(cracen_xof_kats, test_shake128_abc)
{
	struct sx_xof ctx;
	uint8_t out[32];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, kat_msg_abc, sizeof(kat_msg_abc));
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake128_abc_32, sizeof(out), NULL);
}

ZTEST(cracen_xof_kats, test_shake256_abc)
{
	struct sx_xof ctx;
	uint8_t out[32];
	int status;

	status = sx_xof_init(&ctx, &sxhashalg_shake256);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, kat_msg_abc, sizeof(kat_msg_abc));
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out, kat_shake256_abc_32, sizeof(out), NULL);
}

/* ================================================================= */
/* Streaming layer (the load-bearing tests)                           */
/* ================================================================= */

ZTEST_SUITE(cracen_xof_streaming, NULL, cracen_xof_setup, NULL, NULL, NULL);

/* Run a single SHAKE absorb + one-shot squeeze of `total` bytes.
 * Returns the result in `out`. Used as the reference for split-squeeze
 * cross-validation below.
 */
static void shake_oneshot(const struct sxhashalg *alg, const uint8_t *msg, size_t msg_len,
			  uint8_t *out, size_t total)
{
	struct sx_xof ctx;
	int status;

	status = sx_xof_init(&ctx, alg);
	zassert_equal(status, SX_OK, NULL);
	if (msg_len > 0) {
		status = sx_xof_absorb(&ctx, msg, msg_len);
		zassert_equal(status, SX_OK, NULL);
	}
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, total);
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);
}

/* Squeeze `total` bytes via N calls of the given chunk sizes.
 * Verifies the result equals the one-shot reference produced by
 * shake_oneshot(). This is the proof that save_state/resume_state
 * across squeeze invocations actually works on BA418.
 */
static void verify_split_squeeze(const struct sxhashalg *alg, const uint8_t *msg,
				 size_t msg_len, const size_t *chunks, size_t n_chunks,
				 size_t total)
{
	static uint8_t expected[4096];
	static uint8_t got[4096];
	struct sx_xof ctx;
	int status;
	size_t off = 0;

	zassert_true(total <= sizeof(expected), "test buffer too small");

	shake_oneshot(alg, msg, msg_len, expected, total);

	status = sx_xof_init(&ctx, alg);
	zassert_equal(status, SX_OK, NULL);
	if (msg_len > 0) {
		status = sx_xof_absorb(&ctx, msg, msg_len);
		zassert_equal(status, SX_OK, NULL);
	}
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);

	for (size_t i = 0; i < n_chunks; i++) {
		status = sx_xof_squeeze(&ctx, got + off, chunks[i]);
		zassert_equal(status, SX_OK, "chunk %u (size %u): %d", (unsigned)i,
			      (unsigned)chunks[i], status);
		off += chunks[i];
	}
	zassert_equal(off, total, "chunk sizes don't sum to total");
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, total, "split squeeze != one-shot squeeze");
}

/* Test plan #5 - SHAKE-128 split squeeze on a 1 KiB message.
 *
 * Forces multi-block absorb (1024 > 168 = rate) and a multi-rate-block
 * squeeze (512 > 168), with chunk sizes deliberately chosen so that
 * boundaries land both on and off the rate-block boundary.
 */
ZTEST(cracen_xof_streaming, test_shake128_split_squeeze)
{
	uint8_t msg[1024];
	const size_t chunks[] = {37, 113, 1, 167, 194};
	size_t total = 0;

	SKIP_IF_NO_SHAKE128();

	make_test_message(msg, sizeof(msg));
	for (size_t i = 0; i < ARRAY_SIZE(chunks); i++) {
		total += chunks[i];
	}
	verify_split_squeeze(&sxhashalg_shake128, msg, sizeof(msg), chunks, ARRAY_SIZE(chunks),
			     total);
}

/* Same idea, SHAKE-256 (rate 136). */
ZTEST(cracen_xof_streaming, test_shake256_split_squeeze)
{
	uint8_t msg[1024];
	const size_t chunks[] = {1, 135, 1, 136, 137, 102};
	size_t total = 0;

	make_test_message(msg, sizeof(msg));
	for (size_t i = 0; i < ARRAY_SIZE(chunks); i++) {
		total += chunks[i];
	}
	verify_split_squeeze(&sxhashalg_shake256, msg, sizeof(msg), chunks, ARRAY_SIZE(chunks),
			     total);
}

/* test_shake_long_squeeze - emit more output than fits in one
 * SX_XOF_OUT_BUF_SZ refill so the replay/discard path runs at least
 * twice. Cross-validates split vs. one-shot at >2 KB total - the
 * regime where ML-DSA's ExpandA could land on a slow polynomial.
 */
ZTEST(cracen_xof_streaming, test_shake128_long_squeeze)
{
	uint8_t msg[1024];
	/* Total: 1000 + 1000 + 500 + 500 = 3000 bytes
	 * (3000 > 2 * SX_XOF_OUT_BUF_SZ for any default setting up to ~1500).
	 */
	const size_t chunks[] = {1000, 1000, 500, 500};
	size_t total = 0;

	SKIP_IF_NO_SHAKE128();

	make_test_message(msg, sizeof(msg));
	for (size_t i = 0; i < ARRAY_SIZE(chunks); i++) {
		total += chunks[i];
	}
	verify_split_squeeze(&sxhashalg_shake128, msg, sizeof(msg), chunks, ARRAY_SIZE(chunks),
			     total);
}

ZTEST(cracen_xof_streaming, test_shake256_long_squeeze)
{
	uint8_t msg[1024];
	const size_t chunks[] = {1000, 1000, 500, 500};
	size_t total = 0;

	make_test_message(msg, sizeof(msg));
	for (size_t i = 0; i < ARRAY_SIZE(chunks); i++) {
		total += chunks[i];
	}
	verify_split_squeeze(&sxhashalg_shake256, msg, sizeof(msg), chunks, ARRAY_SIZE(chunks),
			     total);
}

/* test_shake_byte_at_a_time - 256 single-byte squeezes must equal one
 * 256-byte squeeze. Maximally stresses the save/resume cycle.
 */
ZTEST(cracen_xof_streaming, test_shake128_byte_at_a_time)
{
	uint8_t msg[64];
	uint8_t expected[256];
	uint8_t got[256];
	struct sx_xof ctx;
	int status;

	SKIP_IF_NO_SHAKE128();

	make_test_message(msg, sizeof(msg));
	shake_oneshot(&sxhashalg_shake128, msg, sizeof(msg), expected, sizeof(expected));

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, msg, sizeof(msg));
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	for (size_t i = 0; i < sizeof(got); i++) {
		status = sx_xof_squeeze(&ctx, &got[i], 1);
		zassert_equal(status, SX_OK, "byte %u: %d", (unsigned)i, status);
	}
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, sizeof(got), NULL);
}

ZTEST(cracen_xof_streaming, test_shake256_byte_at_a_time)
{
	uint8_t msg[64];
	uint8_t expected[256];
	uint8_t got[256];
	struct sx_xof ctx;
	int status;

	make_test_message(msg, sizeof(msg));
	shake_oneshot(&sxhashalg_shake256, msg, sizeof(msg), expected, sizeof(expected));

	status = sx_xof_init(&ctx, &sxhashalg_shake256);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, msg, sizeof(msg));
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	for (size_t i = 0; i < sizeof(got); i++) {
		status = sx_xof_squeeze(&ctx, &got[i], 1);
		zassert_equal(status, SX_OK, "byte %u: %d", (unsigned)i, status);
	}
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, sizeof(got), NULL);
}

/* test_shake_zero_squeeze - sx_xof_squeeze(..., 0) is documented as legal
 * and a no-op. Verify that and that a subsequent non-zero squeeze is unaffected.
 */
ZTEST(cracen_xof_streaming, test_shake_zero_squeeze)
{
	uint8_t expected[64];
	uint8_t got[64];
	struct sx_xof ctx;
	int status;

	SKIP_IF_NO_SHAKE128();

	shake_oneshot(&sxhashalg_shake128, NULL, 0, expected, sizeof(expected));

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);

	status = sx_xof_squeeze(&ctx, got, 0);
	zassert_equal(status, SX_OK, "zero-length squeeze must succeed");
	status = sx_xof_squeeze(&ctx, got, sizeof(got));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, sizeof(got), NULL);
}

/* ================================================================= */
/* Robustness layer                                                   */
/* ================================================================= */

ZTEST_SUITE(cracen_xof_robustness, NULL, cracen_xof_setup, NULL, NULL, NULL);

/* test_shake_absorb_split - feeding the same message in many chunks must
 * produce the same output as feeding it in one shot.
 *
 * Chunk sizes hit the boundaries that historically cause off-by-one bugs:
 * 1 byte, rate-1, exactly rate, rate+1, big.
 */
ZTEST(cracen_xof_robustness, test_shake128_absorb_split)
{
	uint8_t msg[1 + (SHAKE128_RATE - 1) + SHAKE128_RATE + (SHAKE128_RATE + 1) + 256];
	uint8_t expected[64];
	uint8_t got[64];
	struct sx_xof ctx;
	int status;
	const size_t chunks[] = {1, SHAKE128_RATE - 1, SHAKE128_RATE, SHAKE128_RATE + 1, 256};
	size_t off = 0;

	SKIP_IF_NO_SHAKE128();

	make_test_message(msg, sizeof(msg));
	shake_oneshot(&sxhashalg_shake128, msg, sizeof(msg), expected, sizeof(expected));

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(chunks); i++) {
		status = sx_xof_absorb(&ctx, msg + off, chunks[i]);
		zassert_equal(status, SX_OK, "absorb %u: %d", (unsigned)i, status);
		off += chunks[i];
	}
	zassert_equal(off, sizeof(msg), "absorb chunk total mismatch");
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, got, sizeof(got));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, sizeof(got), "absorb-split != one-shot");
}

/* test_shake_reuse - sx_xof_release followed by sx_xof_init on the same
 * stack ctx must produce a fully independent operation. ML-DSA does this
 * heavily (one ctx per matrix-A row, hundreds of times per signature).
 */
ZTEST(cracen_xof_robustness, test_shake_reuse)
{
	struct sx_xof ctx;
	uint8_t out_a[32];
	uint8_t out_b[32];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, kat_msg_abc, sizeof(kat_msg_abc));
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out_a, sizeof(out_a));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	/* Same ctx, same alg, but absorb empty message - must give the empty KAT. */
	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out_b, sizeof(out_b));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out_a, kat_shake128_abc_32, sizeof(out_a),
			  "reused ctx: first op produced wrong KAT");
	zassert_mem_equal(out_b, kat_shake128_empty_64, sizeof(out_b),
			  "reused ctx: second op leaked state from first");
}

/* test_shake_alg_switch - same ctx reused with the other alg. Catches the
 * case where stale internal state (rate, capacity, mode) survives.
 */
ZTEST(cracen_xof_robustness, test_shake_alg_switch)
{
	struct sx_xof ctx;
	uint8_t out128[32];
	uint8_t out256[32];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake256);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out256, sizeof(out256));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out128, sizeof(out128));
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(out256, kat_shake256_empty_64, sizeof(out256), NULL);
	zassert_mem_equal(out128, kat_shake128_empty_64, sizeof(out128), NULL);
}

/* test_shake_concurrent_with_psa_hash - in the middle of an ongoing XOF
 * squeeze loop, run a PSA SHA-256. The XOF holds the BA418 mutex across
 * its own lifecycle; PSA SHA-256 routes through BA413 (a different IP
 * inside CRACEN), but both go through the same DMA controller. If the
 * sx_hw_reserve / sx_hw_release plumbing is wrong for the new XOF caller,
 * this test will deadlock or corrupt one of the two outputs.
 */
ZTEST(cracen_xof_robustness, test_shake_concurrent_with_psa_hash)
{
	struct sx_xof ctx;
	uint8_t expected[256];
	uint8_t got[256];
	uint8_t sha_out[32];
	size_t sha_len;
	psa_status_t ps;
	int status;

	SKIP_IF_NO_SHAKE128();

	shake_oneshot(&sxhashalg_shake128, NULL, 0, expected, sizeof(expected));

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);

	/* First half via the XOF. */
	status = sx_xof_squeeze(&ctx, got, 128);
	zassert_equal(status, SX_OK, NULL);

	/* Run a PSA SHA-256 on a small message while the XOF context is
	 * still alive. Result is irrelevant; only the absence of corruption
	 * matters.
	 */
	const uint8_t sha_in[8] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe};

	ps = psa_hash_compute(PSA_ALG_SHA_256, sha_in, sizeof(sha_in), sha_out, sizeof(sha_out),
			      &sha_len);
	zassert_equal(ps, PSA_SUCCESS, "psa_hash_compute(SHA-256) failed: %d", (int)ps);
	zassert_equal(sha_len, 32, NULL);

	/* Second half via the XOF - must continue from where we left off. */
	status = sx_xof_squeeze(&ctx, got + 128, 128);
	zassert_equal(status, SX_OK, NULL);
	sx_xof_release(&ctx);

	zassert_mem_equal(got, expected, sizeof(got),
			  "XOF output corrupted by intervening PSA hash");
}

/* test_shake128_finalize_after_finalize - finalize twice must error,
 * not crash.
 */
ZTEST(cracen_xof_robustness, test_shake_double_finalize)
{
	struct sx_xof ctx;
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_not_equal(status, SX_OK, "second finalize should error");
	sx_xof_release(&ctx);
}

/* test_shake_squeeze_before_finalize - squeeze before finalize must error. */
ZTEST(cracen_xof_robustness, test_shake_squeeze_before_finalize)
{
	struct sx_xof ctx;
	uint8_t out[16];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_squeeze(&ctx, out, sizeof(out));
	zassert_not_equal(status, SX_OK, "squeeze before finalize should error");
	sx_xof_release(&ctx);
}

/* test_shake_absorb_after_finalize - absorb after finalize must error. */
ZTEST(cracen_xof_robustness, test_shake_absorb_after_finalize)
{
	struct sx_xof ctx;
	uint8_t buf[16];
	int status;

	SKIP_IF_NO_SHAKE128();

	status = sx_xof_init(&ctx, &sxhashalg_shake128);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_finalize(&ctx);
	zassert_equal(status, SX_OK, NULL);
	status = sx_xof_absorb(&ctx, buf, sizeof(buf));
	zassert_not_equal(status, SX_OK, "absorb after finalize should error");
	sx_xof_release(&ctx);
}
