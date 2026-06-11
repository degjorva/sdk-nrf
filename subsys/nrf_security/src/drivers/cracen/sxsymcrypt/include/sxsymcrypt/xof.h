/** Streaming SHAKE-128 / SHAKE-256 extendable-output (XOF) API.
 *
 * @file
 *
 * @copyright Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Internal CRACEN API. Not exposed at the PSA level. Intended for use by
 * lattice / hash-based PQC primitives that follow the FIPS 202
 * "absorb-once, squeeze-many" pattern (e.g. ML-DSA, ML-KEM, SLH-DSA).
 *
 * Typical usage:
 * @code
 *   struct sx_xof ctx;
 *
 *   sx_xof_init(&ctx, &sxhashalg_shake128);
 *   sx_xof_absorb(&ctx, seed, sizeof(seed));
 *   sx_xof_absorb(&ctx, &index, 1);
 *   sx_xof_finalize(&ctx);
 *
 *   // Squeeze can be called any number of times, with any sizes:
 *   sx_xof_squeeze(&ctx, buf1, 168);
 *   sx_xof_squeeze(&ctx, buf2, 17);
 *   sx_xof_squeeze(&ctx, buf3, 4096);
 *
 *   sx_xof_release(&ctx);
 * @endcode
 */

#ifndef XOF_HEADER_FILE
#define XOF_HEADER_FILE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sxsymcrypt/hashdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum SHAKE rate in bytes (SHAKE-128 has the larger of the two rates). */
#define SX_XOF_MAX_RATE 168

/** Per-context output buffer size used by sx_xof_squeeze() refills.
 *
 * Each refill replays the absorbed message through the BA418 (it does not
 * support output continuation), discarding any previously-emitted prefix
 * and capturing the next ::CONFIG_CRACEN_XOF_OUT_BUF_SZ bytes. Bigger
 * buffer = fewer HW invocations per squeeze chain. Default 1008 B (6
 * SHAKE-128 rate blocks) satisfies a typical ML-DSA ExpandA polynomial in
 * one HW call.
 */
#define SX_XOF_OUT_BUF_SZ CONFIG_CRACEN_XOF_OUT_BUF_SZ

/** Maximum absorb-message length supported by the streaming XOF.
 *
 * The wrapper buffers the entire absorbed message in the context so each
 * squeeze refill can replay it. Absorbs larger than this return
 * ::SX_ERR_TOO_BIG. Tunable via ::CONFIG_CRACEN_XOF_MSG_BUF_SZ; default
 * 1280 B covers ML-DSA / ML-KEM seeds (<100 B) plus the worst-case
 * SHAKE pad (168 B for SHAKE-128).
 */
#define SX_XOF_MSG_BUF_SZ CONFIG_CRACEN_XOF_MSG_BUF_SZ

/** A streaming XOF operation context.
 *
 * All members should be considered INTERNAL and may not be accessed directly.
 * Allocate one of these on the stack/heap of the caller.
 */
struct sx_xof {
	struct sxhash hash;                /**< Underlying BA418 hash context. */
	uint8_t msg[SX_XOF_MSG_BUF_SZ];    /**< Absorbed message + SHAKE pad. */
	size_t msg_len;                    /**< Bytes valid in msg[]. */
	size_t prev_squeezed;              /**< Bytes already emitted to caller. */
	uint8_t out_buf[SX_XOF_OUT_BUF_SZ];/**< Tail of latest HW squeeze. */
	size_t out_pos;                    /**< Next byte to deliver. */
	size_t out_avail;                  /**< Valid bytes in out_buf. */
	bool finalized;                    /**< True after sx_xof_finalize(). */
};

/** Initialize an XOF context for SHAKE-128 or SHAKE-256.
 *
 * @param[out] ctx XOF context.
 * @param[in]  alg Either &sxhashalg_shake128 or &sxhashalg_shake256.
 *
 * @retval ::SX_OK on success.
 * @retval ::SX_ERR_INCOMPATIBLE_HW on HW reservation failure.
 * @retval ::SX_ERR_RETRY if the BA418 is busy.
 */
int sx_xof_init(struct sx_xof *ctx, const struct sxhashalg *alg);

/** Absorb message bytes.
 *
 * May be called multiple times. The total absorbed length is unbounded.
 * Cannot be called after sx_xof_finalize().
 *
 * @param[in,out] ctx XOF context.
 * @param[in]     data bytes to absorb.
 * @param[in]     len number of bytes to absorb.
 *
 * @retval ::SX_OK on success.
 * @retval ::SX_ERR_UNINITIALIZED_OBJ if ctx was not initialized.
 * @retval ::SX_ERR_FEED_AFTER_DATA if called after sx_xof_finalize().
 */
int sx_xof_absorb(struct sx_xof *ctx, const uint8_t *data, size_t len);

/** Apply SHAKE padding and prepare the XOF for squeezing.
 *
 * After this call no more sx_xof_absorb() calls are permitted; only
 * sx_xof_squeeze() and sx_xof_release().
 *
 * @param[in,out] ctx XOF context.
 *
 * @retval ::SX_OK on success.
 * @retval ::SX_ERR_UNINITIALIZED_OBJ if ctx was not initialized.
 * @retval ::SX_ERR_FEED_AFTER_DATA if called twice.
 */
int sx_xof_finalize(struct sx_xof *ctx);

/** Squeeze output bytes.
 *
 * May be called any number of times with any size, including 0. The
 * concatenation of all squeezed bytes equals the FIPS 202 SHAKE
 * output for the absorbed message.
 *
 * @param[in,out] ctx XOF context.
 * @param[out]    out output buffer.
 * @param[in]     len number of bytes to produce.
 *
 * @retval ::SX_OK on success.
 * @retval ::SX_ERR_UNINITIALIZED_OBJ if ctx was not initialized
 *         or sx_xof_finalize() was not called.
 */
int sx_xof_squeeze(struct sx_xof *ctx, uint8_t *out, size_t len);

/** Release the underlying BA418 HW resource.
 *
 * Must be called when done. After this, ctx may be reused with sx_xof_init().
 *
 * @param[in,out] ctx XOF context.
 */
void sx_xof_release(struct sx_xof *ctx);

#ifdef __cplusplus
}
#endif

#endif /* XOF_HEADER_FILE */
