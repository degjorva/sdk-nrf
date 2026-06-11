/*
 *  Copyright (c) 2026 Nordic Semiconductor ASA
 *
 *  SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 *  Streaming SHAKE-128/256 XOF API on top of the BA418 hash core.
 *
 *  ## Why this wrapper exists
 *
 *  The BA418 is not a streaming XOF: the output length is programmed once
 *  in the cfgword and produced in a single DMA pass; there is no squeeze
 *  continuation. The hardware context-save mechanism preserves the
 *  1600-bit Keccak state for splitting *input* absorb across DMA
 *  boundaries, not for resuming *output*. (Empirically: setting
 *  SAVE_CONTEXT and a non-zero outlen in the same cfgword hangs the IP
 *  on nRF54L15 BA418 r1.)
 *
 *  ML-DSA's ExpandA, ExpandS, and SampleInBall consume a rejection-driven,
 *  variable number of output bytes that cannot be predicted up front, so
 *  this wrapper offers an "absorb-once, squeeze-many" facade on top of
 *  the BA418's one-shot fixed-output mode.
 *
 *  ## Replay strategy (relies on prefix-stability of SHAKE)
 *
 *  SHAKE output is prefix-stable: SHAKE-X(msg, N+M) byte-equals
 *  SHAKE-X(msg, N) followed by additional bytes for any N, M >= 0.
 *  Replaying a SHAKE call with a longer outlen reproduces the previously
 *  emitted prefix identically. That is the property that makes this
 *  wrapper correct.
 *
 *    - sx_xof_absorb() copies the message bytes into ctx->msg[].
 *    - sx_xof_finalize() appends the SHAKE pad in-place; ctx->msg[] now
 *      holds the rate-block-aligned padded message (no HW call).
 *    - sx_xof_squeeze() serves bytes from ctx->out_buf when available;
 *      when the buffer empties, it issues a one-shot BA418 call asking
 *      for prev_squeezed + SX_XOF_OUT_BUF_SZ bytes. The first
 *      prev_squeezed bytes are routed through DMA_DISCARD descriptors
 *      so the BA418 emits the full prefix but the CPU only sees the
 *      next chunk (stored in ctx->out_buf). prev_squeezed advances by
 *      SX_XOF_OUT_BUF_SZ each refill.
 *
 *  The default chunk size (1008 B = 6 SHAKE-128 rate blocks) is tuned so
 *  that a typical ML-DSA ExpandA polynomial (~768 B) is satisfied in one
 *  HW call; bigger chunks reduce HW invocations at the cost of more
 *  BA418 work per refill (the message must be re-permuted to reach the
 *  larger outlen). For squeeze chains beyond a few KB the per-refill
 *  cost grows linearly in prev_squeezed, so total work is O(N^2) in the
 *  number of refills - acceptable for sub-tens-of-KB total squeeze (the
 *  realistic PQC envelope).
 *
 *  ## Future-proofing
 *
 *  The external API (sx_xof_init/absorb/finalize/squeeze/release) does
 *  not encode the replay strategy anywhere. A future BA418 revision (or
 *  a SW Keccak backend in cracen_sw/ext) that supports true streaming
 *  squeeze can drop in by reimplementing xof_emit_block() without
 *  touching callers.
 */

#include <sxsymcrypt/xof.h>
#include <sxsymcrypt/hash.h>
#include <sxsymcrypt/hashdefs.h>
#include <sxsymcrypt/internal.h>

#include <cracen/statuscodes.h>

#ifdef CONFIG_DCACHE
#include <zephyr/cache.h>
#endif

#include <string.h>

#include "cmdma.h"
#include "sha3_internal.h"

static int xof_check_alg(const struct sxhashalg *alg)
{
	if (alg == &sxhashalg_shake128) {
		return SX_OK;
	}
	if (alg == &sxhashalg_shake256) {
		return SX_OK;
	}
	return SX_ERR_INCOMPATIBLE_HW;
}

/* Maximum chunk of bytes we ever ask the BA418 to discard in one descriptor.
 * The CRACEN DMA size field is 24 bits (DMA_SZ_MASK), so 16 MiB - 1 is the
 * absolute upper bound; we cap at 64 KiB so that the discard fits in one
 * descriptor for any realistic squeeze chain.
 */
#define XOF_MAX_DISCARD_PER_DESC (1u << 16)

/* Run one HW pass: feed ctx->msg[..msg_len], request prev_squeezed + chunk
 * bytes of SHAKE output, discard the first prev_squeezed bytes via the DMA,
 * and write the last chunk bytes into ctx->out_buf. Stores no Keccak state -
 * each call permutes from scratch (correctness comes from prefix-stability
 * of SHAKE: previously-emitted bytes are reproduced byte-for-byte).
 */
static int xof_emit_block(struct sx_xof *ctx)
{
	struct sxhash *h = &ctx->hash;
	const size_t chunk = SX_XOF_OUT_BUF_SZ;
	const size_t prev = ctx->prev_squeezed;
	const size_t total_out = prev + chunk;

	int status = sx_hw_reserve(&h->dma, SX_HW_RESERVE_DEFAULT);

	if (status != SX_OK) {
		return status;
	}

	status = h->algo->reservehw(h, sizeof(*h));
	if (status != SX_OK) {
		sx_hw_release(&h->dma);
		return status;
	}

	/* Feed the full padded message in one descriptor. ADD_INDESC_PRIV_RAW
	 * is required because BA418 doesn't support byte-ignore flags
	 * (mirroring shake256_digest's comment).
	 */
	if (ctx->msg_len > 0) {
		ADD_RAW_INDESC(h->dma, ctx->msg, ctx->msg_len, h->dmatags->data);
	}

	/* Patch outlen into cfg word (the algo's cfgword has outlen=0 baked in
	 * exactly so this OR is correct after sx_cmdma_newcmd reset cfg).
	 */
	h->dma.dmamem.cfg |= ((uint32_t)total_out << SHA3_OUTLEN_SHIFT);

	/* Output: discard prev bytes, then capture chunk bytes. The DMA splits
	 * the HW output stream across descriptors in order, so this gives us
	 * the squeeze tail for the current refill.
	 */
	size_t to_discard = prev;

	while (to_discard > 0) {
		size_t d = (to_discard > XOF_MAX_DISCARD_PER_DESC) ?
				   XOF_MAX_DISCARD_PER_DESC : to_discard;
		ADD_DISCARDDESC(h->dma, d);
		to_discard -= d;
	}
	ADD_OUTDESCA(h->dma, ctx->out_buf, chunk, CMDMA_BA418_BUS_MSK);

	sx_cmdma_start(&h->dma, sizeof(h->descs) + sizeof(h->extramem), h->descs);

	status = sx_hash_wait(h);
	sx_hw_release(&h->dma);

	if (status != SX_OK) {
		return status;
	}

#ifdef CONFIG_DCACHE
	sys_cache_data_invd_range((void *)ctx->out_buf, chunk);
#endif

	ctx->out_pos = 0;
	ctx->out_avail = chunk;
	ctx->prev_squeezed = total_out;
	return SX_OK;
}

int sx_xof_init(struct sx_xof *ctx, const struct sxhashalg *alg)
{
	int status = xof_check_alg(alg);

	if (status != SX_OK) {
		return status;
	}

	memset(&ctx->hash, 0, sizeof(ctx->hash));
	ctx->hash.algo = alg;
	ctx->msg_len = 0;
	ctx->prev_squeezed = 0;
	ctx->out_pos = 0;
	ctx->out_avail = 0;
	ctx->finalized = false;

	return SX_OK;
}

int sx_xof_absorb(struct sx_xof *ctx, const uint8_t *data, size_t len)
{
	if (!ctx->hash.algo) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	if (ctx->finalized) {
		return SX_ERR_FEED_AFTER_DATA;
	}
	if (len == 0) {
		return SX_OK;
	}
	if (ctx->msg_len + len > sizeof(ctx->msg)) {
		/* The replay strategy needs the whole message in ctx->msg.
		 * Bump CRACEN_XOF_MSG_BUF_SZ if you need bigger absorbs.
		 */
		return SX_ERR_TOO_BIG;
	}

	memcpy(ctx->msg + ctx->msg_len, data, len);
	ctx->msg_len += len;
	return SX_OK;
}

int sx_xof_finalize(struct sx_xof *ctx)
{
	struct sxhash *h = &ctx->hash;

	if (!h->algo) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	if (ctx->finalized) {
		return SX_ERR_FEED_AFTER_DATA;
	}

	const size_t rate = h->algo->blocksz;
	const size_t capacity = h->algo->statesz - rate;
	const size_t avail = sizeof(ctx->msg) - ctx->msg_len;

	/* Worst-case SHAKE pad is one full rate block when the message ends on
	 * a rate boundary. Make sure the in-place pad fits.
	 */
	if (avail < rate) {
		return SX_ERR_TOO_BIG;
	}

	size_t padsz = sha3_fips202_pad(SHAKE_MODE_PREFIX, SHAKE_MODE_SUFFIX, capacity,
					ctx->msg_len, ctx->msg + ctx->msg_len);
	ctx->msg_len += padsz;
	ctx->finalized = true;
	return SX_OK;
}

int sx_xof_squeeze(struct sx_xof *ctx, uint8_t *out, size_t len)
{
	if (!ctx->hash.algo) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}
	if (!ctx->finalized) {
		return SX_ERR_UNINITIALIZED_OBJ;
	}

	while (len > 0) {
		if (ctx->out_pos == ctx->out_avail) {
			int status = xof_emit_block(ctx);

			if (status != SX_OK) {
				return status;
			}
		}

		size_t avail = ctx->out_avail - ctx->out_pos;
		size_t copy = (avail < len) ? avail : len;

		memcpy(out, &ctx->out_buf[ctx->out_pos], copy);
		ctx->out_pos += copy;
		out += copy;
		len -= copy;
	}

	return SX_OK;
}

void sx_xof_release(struct sx_xof *ctx)
{
	/* No persistent HW reservation - each squeeze refill reserves and
	 * releases BA418 by itself. Just clear local state.
	 */
	memset(ctx->msg, 0, sizeof(ctx->msg));
	memset(ctx->out_buf, 0, sizeof(ctx->out_buf));
	ctx->msg_len = 0;
	ctx->prev_squeezed = 0;
	ctx->out_pos = 0;
	ctx->out_avail = 0;
	ctx->finalized = false;
	ctx->hash.algo = NULL;
}
