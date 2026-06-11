/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * cracen_ml_dsa_verify - round-trip tests for the CRACEN ML-DSA verify
 * PSA driver against the Oberon ML-DSA sign driver.
 *
 * The test strategy is:
 *   1. Generate an ML-DSA key pair on Oberon (`psa_generate_key`).
 *   2. Sign a known message + context with that key pair on Oberon
 *      (`psa_sign_message_with_context`).
 *   3. Export the public key, import it as a stand-alone
 *      `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` (which routes through the
 *      CRACEN import path -- see cracen_psa_key_management.c) and
 *      verify the signature (`psa_verify_message_with_context`). PSA
 *      dispatches verify to CRACEN because CRACEN selects
 *      PSA_ACCEL_ML_DSA_VERIFY for the matching parameter set.
 *   4. Flip a bit in the signature and re-verify; expect
 *      PSA_ERROR_INVALID_SIGNATURE.
 *
 * All three parameter sets (44, 65, 87) are exercised, both with empty
 * and non-empty FIPS 204 context strings, and both for pure ML-DSA and
 * for HashML-DSA(SHA-256).
 *
 * Because Oberon's `PSA_NEED_OBERON_ML_DSA_SIGN` is only gated on
 * `!PSA_ACCEL_ML_DSA` (and not on `!PSA_ACCEL_ML_DSA_VERIFY`), Oberon
 * remains responsible for sign / keygen even though CRACEN now claims
 * verify -- this split is exactly the configuration the test validates.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <string.h>

LOG_MODULE_REGISTER(cracen_ml_dsa_verify_test, LOG_LEVEL_INF);

/* MLDSA public key + signature sizes per FIPS 204. */
#define ML_DSA_44_PK_SIZE  1312u
#define ML_DSA_44_SIG_SIZE 2420u
#define ML_DSA_65_PK_SIZE  1952u
#define ML_DSA_65_SIG_SIZE 3309u
#define ML_DSA_87_PK_SIZE  2592u
#define ML_DSA_87_SIG_SIZE 4627u

/* Worst case (ML-DSA-87) sizes for stack-allocated buffers below. */
#define ML_DSA_PK_MAX  ML_DSA_87_PK_SIZE
#define ML_DSA_SIG_MAX ML_DSA_87_SIG_SIZE

static const uint8_t test_message[] = {
	'C', 'R', 'A', 'C', 'E', 'N', '-', 'M', 'L', '-', 'D', 'S', 'A',
	' ', 'v', 'e', 'r', 'i', 'f', 'y', ' ', 'r', 'o', 'u', 'n', 'd',
	'-', 't', 'r', 'i', 'p', ' ', 't', 'e', 's', 't', ' ', 'v', 'e',
	'c', 't', 'o', 'r', '.',
};

/* A non-empty context within FIPS 204's 0..255 byte limit. */
static const uint8_t test_context[] = {
	'c', 'r', 'a', 'c', 'e', 'n', '/', 't', 'e', 's', 't', '@', '1',
};

/* SHA-256 digest of test_message, for HashML-DSA-SHA-256 tests. */
static uint8_t test_message_sha256[32];

static void *cracen_ml_dsa_setup(void)
{
	psa_status_t ps = psa_crypto_init();
	size_t hash_length = 0;

	zassert_true(ps == PSA_SUCCESS || ps == PSA_ERROR_ALREADY_EXISTS,
		     "psa_crypto_init failed: %d", (int)ps);

	ps = psa_hash_compute(PSA_ALG_SHA_256, test_message, sizeof(test_message),
			      test_message_sha256, sizeof(test_message_sha256), &hash_length);
	zassert_equal(ps, PSA_SUCCESS, "psa_hash_compute(SHA-256): %d", (int)ps);
	zassert_equal(hash_length, sizeof(test_message_sha256),
		      "unexpected SHA-256 digest length: %zu", hash_length);
	return NULL;
}

ZTEST_SUITE(cracen_ml_dsa_verify, NULL, cracen_ml_dsa_setup, NULL, NULL, NULL);

/* Helper to expose the pk bytes / sig bytes for a given key_bits, or 0
 * if the parameter set is not configured into this build. */
static size_t ml_dsa_pk_bytes_for_bits(size_t bits)
{
	switch (bits) {
	case 128: return ML_DSA_44_PK_SIZE;
	case 192: return ML_DSA_65_PK_SIZE;
	case 256: return ML_DSA_87_PK_SIZE;
	default:  return 0;
	}
}

static size_t ml_dsa_sig_bytes_for_bits(size_t bits)
{
	switch (bits) {
	case 128: return ML_DSA_44_SIG_SIZE;
	case 192: return ML_DSA_65_SIG_SIZE;
	case 256: return ML_DSA_87_SIG_SIZE;
	default:  return 0;
	}
}

/* Set up attributes for a freshly-generated ML-DSA key pair. */
static void make_keypair_attributes(psa_key_attributes_t *attr, size_t bits)
{
	psa_set_key_type(attr, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
	psa_set_key_bits(attr, bits);
	psa_set_key_algorithm(attr, PSA_ALG_ML_DSA);
	psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_MESSAGE |
					      PSA_KEY_USAGE_SIGN_HASH |
					      PSA_KEY_USAGE_VERIFY_MESSAGE |
					      PSA_KEY_USAGE_VERIFY_HASH |
					      PSA_KEY_USAGE_EXPORT);
}

static void make_public_attributes(psa_key_attributes_t *attr, size_t bits)
{
	psa_set_key_type(attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
	psa_set_key_bits(attr, bits);
	psa_set_key_algorithm(attr, PSA_ALG_ML_DSA);
	psa_set_key_usage_flags(attr, PSA_KEY_USAGE_VERIFY_MESSAGE |
					      PSA_KEY_USAGE_VERIFY_HASH);
}

/* Common engine: generate keypair on Oberon, sign on Oberon, import
 * the public key on CRACEN, verify on CRACEN, tamper, verify again.
 *
 * @param bits     PSA key_bits identifying the parameter set: 128/192/256.
 * @param context  Optional FIPS 204 context string; may be NULL when
 *                 context_length == 0.
 */
static void run_pure_ml_dsa_round_trip(size_t bits, const uint8_t *context,
				       size_t context_length)
{
	psa_status_t ps;
	psa_key_attributes_t kp_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t pk_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_pair_id = PSA_KEY_ID_NULL;
	psa_key_id_t public_key_id = PSA_KEY_ID_NULL;
	uint8_t pk[ML_DSA_PK_MAX];
	uint8_t sig[ML_DSA_SIG_MAX];
	size_t pk_len = 0;
	size_t sig_len = 0;
	const size_t expected_pk = ml_dsa_pk_bytes_for_bits(bits);
	const size_t expected_sig = ml_dsa_sig_bytes_for_bits(bits);

	zassert_not_equal(expected_pk, 0, "unsupported bits=%zu", bits);

	make_keypair_attributes(&kp_attr, bits);
	ps = psa_generate_key(&kp_attr, &key_pair_id);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_generate_key(ML-DSA, bits=%zu): %d", bits, (int)ps);

	ps = psa_export_public_key(key_pair_id, pk, sizeof(pk), &pk_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_export_public_key(ML-DSA, bits=%zu): %d", bits, (int)ps);
	zassert_equal(pk_len, expected_pk,
		      "exported pk length mismatch bits=%zu: %zu vs %zu",
		      bits, pk_len, expected_pk);

	ps = psa_sign_message_with_context(key_pair_id, PSA_ALG_ML_DSA, test_message,
					   sizeof(test_message), context, context_length,
					   sig, sizeof(sig), &sig_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_sign_message_with_context(ML-DSA, bits=%zu): %d",
		      bits, (int)ps);
	zassert_equal(sig_len, expected_sig,
		      "signature length mismatch bits=%zu: %zu vs %zu",
		      bits, sig_len, expected_sig);

	make_public_attributes(&pk_attr, bits);
	ps = psa_import_key(&pk_attr, pk, pk_len, &public_key_id);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_import_key(ML-DSA pub, bits=%zu): %d", bits, (int)ps);

	/* Happy path - this is the actual CRACEN verify under test. */
	ps = psa_verify_message_with_context(public_key_id, PSA_ALG_ML_DSA, test_message,
					     sizeof(test_message), context, context_length,
					     sig, sig_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "verify_message_with_context (good sig) bits=%zu: %d",
		      bits, (int)ps);

	/* Tamper a byte deep in the signature (well past the c̃ tag at the
	 * start) and confirm CRACEN reports it as invalid. Pick a position
	 * after the first rate block to make sure the corruption is
	 * actually consumed by ExpandMask/UseHint. */
	sig[sig_len / 2] ^= 0x40;
	ps = psa_verify_message_with_context(public_key_id, PSA_ALG_ML_DSA, test_message,
					     sizeof(test_message), context, context_length,
					     sig, sig_len);
	zassert_equal(ps, PSA_ERROR_INVALID_SIGNATURE,
		      "verify_message_with_context (tampered sig) bits=%zu: %d",
		      bits, (int)ps);

	(void)psa_destroy_key(key_pair_id);
	(void)psa_destroy_key(public_key_id);
}

static void run_hash_ml_dsa_round_trip(size_t bits, const uint8_t *context,
				       size_t context_length)
{
	psa_status_t ps;
	psa_key_attributes_t kp_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t pk_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_pair_id = PSA_KEY_ID_NULL;
	psa_key_id_t public_key_id = PSA_KEY_ID_NULL;
	const psa_algorithm_t alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256);
	uint8_t pk[ML_DSA_PK_MAX];
	uint8_t sig[ML_DSA_SIG_MAX];
	size_t pk_len = 0;
	size_t sig_len = 0;
	const size_t expected_pk = ml_dsa_pk_bytes_for_bits(bits);
	const size_t expected_sig = ml_dsa_sig_bytes_for_bits(bits);

	zassert_not_equal(expected_pk, 0, "unsupported bits=%zu", bits);

	make_keypair_attributes(&kp_attr, bits);
	psa_set_key_algorithm(&kp_attr, alg);
	ps = psa_generate_key(&kp_attr, &key_pair_id);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_generate_key(HashML-DSA, bits=%zu): %d", bits, (int)ps);

	ps = psa_export_public_key(key_pair_id, pk, sizeof(pk), &pk_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_export_public_key(HashML-DSA, bits=%zu): %d", bits, (int)ps);

	ps = psa_sign_hash_with_context(key_pair_id, alg, test_message_sha256,
					sizeof(test_message_sha256), context, context_length,
					sig, sizeof(sig), &sig_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_sign_hash_with_context(HashML-DSA, bits=%zu): %d",
		      bits, (int)ps);
	zassert_equal(sig_len, expected_sig,
		      "signature length mismatch bits=%zu: %zu vs %zu",
		      bits, sig_len, expected_sig);

	make_public_attributes(&pk_attr, bits);
	psa_set_key_algorithm(&pk_attr, alg);
	ps = psa_import_key(&pk_attr, pk, pk_len, &public_key_id);
	zassert_equal(ps, PSA_SUCCESS,
		      "psa_import_key(HashML-DSA pub, bits=%zu): %d", bits, (int)ps);

	ps = psa_verify_hash_with_context(public_key_id, alg, test_message_sha256,
					  sizeof(test_message_sha256), context, context_length,
					  sig, sig_len);
	zassert_equal(ps, PSA_SUCCESS,
		      "verify_hash_with_context (good sig) bits=%zu: %d",
		      bits, (int)ps);

	sig[sig_len / 2] ^= 0x40;
	ps = psa_verify_hash_with_context(public_key_id, alg, test_message_sha256,
					  sizeof(test_message_sha256), context, context_length,
					  sig, sig_len);
	zassert_equal(ps, PSA_ERROR_INVALID_SIGNATURE,
		      "verify_hash_with_context (tampered sig) bits=%zu: %d",
		      bits, (int)ps);

	(void)psa_destroy_key(key_pair_id);
	(void)psa_destroy_key(public_key_id);
}

/* === Pure ML-DSA, empty context === */

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_44_empty_ctx)
{
	run_pure_ml_dsa_round_trip(128, NULL, 0);
}

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_65_empty_ctx)
{
	run_pure_ml_dsa_round_trip(192, NULL, 0);
}

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_87_empty_ctx)
{
	run_pure_ml_dsa_round_trip(256, NULL, 0);
}

/* === Pure ML-DSA, non-empty context === */

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_44_with_ctx)
{
	run_pure_ml_dsa_round_trip(128, test_context, sizeof(test_context));
}

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_65_with_ctx)
{
	run_pure_ml_dsa_round_trip(192, test_context, sizeof(test_context));
}

ZTEST(cracen_ml_dsa_verify, test_pure_ml_dsa_87_with_ctx)
{
	run_pure_ml_dsa_round_trip(256, test_context, sizeof(test_context));
}

/* === HashML-DSA(SHA-256), empty context === */

ZTEST(cracen_ml_dsa_verify, test_hash_ml_dsa_sha256_44)
{
	run_hash_ml_dsa_round_trip(128, NULL, 0);
}

ZTEST(cracen_ml_dsa_verify, test_hash_ml_dsa_sha256_65)
{
	run_hash_ml_dsa_round_trip(192, NULL, 0);
}

ZTEST(cracen_ml_dsa_verify, test_hash_ml_dsa_sha256_87)
{
	run_hash_ml_dsa_round_trip(256, NULL, 0);
}

/* Import + export round-trip without verify: exercises the dedicated
 * CRACEN key-management path independently from the lattice math. */
static void run_pk_import_export_round_trip(size_t bits)
{
	psa_status_t ps;
	psa_key_attributes_t kp_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t pk_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_pair_id = PSA_KEY_ID_NULL;
	psa_key_id_t public_key_id = PSA_KEY_ID_NULL;
	uint8_t pk[ML_DSA_PK_MAX];
	uint8_t pk_re_exported[ML_DSA_PK_MAX];
	size_t pk_len = 0;
	size_t re_exported_len = 0;
	const size_t expected_pk = ml_dsa_pk_bytes_for_bits(bits);

	zassert_not_equal(expected_pk, 0, "unsupported bits=%zu", bits);

	make_keypair_attributes(&kp_attr, bits);
	ps = psa_generate_key(&kp_attr, &key_pair_id);
	zassert_equal(ps, PSA_SUCCESS, NULL);

	ps = psa_export_public_key(key_pair_id, pk, sizeof(pk), &pk_len);
	zassert_equal(ps, PSA_SUCCESS, NULL);
	zassert_equal(pk_len, expected_pk, NULL);

	make_public_attributes(&pk_attr, bits);
	ps = psa_import_key(&pk_attr, pk, pk_len, &public_key_id);
	zassert_equal(ps, PSA_SUCCESS, "psa_import_key bits=%zu: %d", bits, (int)ps);

	ps = psa_export_public_key(public_key_id, pk_re_exported, sizeof(pk_re_exported),
				   &re_exported_len);
	zassert_equal(ps, PSA_SUCCESS, "psa_export_public_key bits=%zu: %d", bits, (int)ps);
	zassert_equal(re_exported_len, expected_pk, NULL);
	zassert_mem_equal(pk_re_exported, pk, expected_pk,
			  "re-exported public key bits=%zu differs from imported", bits);

	(void)psa_destroy_key(key_pair_id);
	(void)psa_destroy_key(public_key_id);
}

ZTEST(cracen_ml_dsa_verify, test_pk_import_export_44)
{
	run_pk_import_export_round_trip(128);
}

ZTEST(cracen_ml_dsa_verify, test_pk_import_export_65)
{
	run_pk_import_export_round_trip(192);
}

ZTEST(cracen_ml_dsa_verify, test_pk_import_export_87)
{
	run_pk_import_export_round_trip(256);
}
