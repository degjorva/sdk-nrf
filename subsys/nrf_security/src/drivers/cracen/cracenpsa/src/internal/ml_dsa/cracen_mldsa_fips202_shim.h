/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * FIPS-202 backend shim that routes mldsa-native's SHAKE-128 and
 * SHAKE-256 calls onto the CRACEN BA418 via sx_xof_*().
 *
 * mldsa-native is configured to use this header by
 * MLD_CONFIG_FIPS202_CUSTOM_HEADER in cracen_mldsa_config.h. The API
 * surface it must replace is described in
 *   modules/crypto/mldsa-native/mldsa/src/fips202/fips202.h
 *   modules/crypto/mldsa-native/FIPS202.md
 * with one exception: MLD_CONFIG_SERIAL_FIPS202_ONLY removes the 4-way
 * batched API, so no x4 shim is required.
 *
 * Multi-level inclusion
 * ---------------------
 * mldsa-native pulls in symmetric.h (and thus this header) once per
 * parameter set in the SCU build, but the FIPS 202 API is itself
 * parameter-set-independent: MLD_NAMESPACE(shake256_init) expands to
 * cracen_mldsa_shake256_init regardless of MLD_CONFIG_PARAMETER_SET
 * (see MLD_NAMESPACE in mldsa-native/mldsa/src/common.h; only
 * MLD_NAMESPACE_KL adds the 44/65/87 suffix). So one inclusion guard
 * is sufficient: every include after the first is a no-op.
 *
 * State handling
 * --------------
 * The ctx is allocated on mldsa-native's stack and passed in by
 * reference; we embed a full struct sx_xof inside it so there are no
 * file-scope statics. sx_xof_init/_absorb errors are latched in
 * ctx->failed; subsequent squeeze() calls zero their output so
 * verify_internal fails closed instead of consuming uninitialized
 * memory.
 */

#ifndef CRACEN_MLDSA_FIPS202_SHIM_H
#define CRACEN_MLDSA_FIPS202_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sxsymcrypt/xof.h>
#include <sxsymcrypt/hashdefs.h>
#include <cracen/statuscodes.h>

/* mldsa-native's sys.h defines MLD_INLINE without "static" (it is meant
 * to be combined as "static MLD_INLINE"). Provide a fallback for
 * standalone editing. */
#ifndef MLD_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define MLD_INLINE __attribute__((always_inline)) inline
#else
#define MLD_INLINE inline
#endif
#endif

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define MLD_KECCAK_LANES 25
#define SHA3_256_HASHBYTES 32
#define SHA3_512_HASHBYTES 64

struct cracen_mldsa_shake_state {
	struct sx_xof xof;
	bool initialized;
	bool failed;
};

typedef struct cracen_mldsa_shake_state mld_shake128ctx;
typedef struct cracen_mldsa_shake_state mld_shake256ctx;

static MLD_INLINE void cracen_mldsa_shake_init(struct cracen_mldsa_shake_state *s,
					       const struct sxhashalg *alg)
{
	s->initialized = false;
	s->failed = false;

	int err = sx_xof_init(&s->xof, alg);

	if (err != SX_OK) {
		s->failed = true;
		return;
	}
	s->initialized = true;
}

static MLD_INLINE void cracen_mldsa_shake_absorb(struct cracen_mldsa_shake_state *s,
						 const uint8_t *in, size_t inlen)
{
	if (s->failed || !s->initialized) {
		s->failed = true;
		return;
	}
	if (sx_xof_absorb(&s->xof, in, inlen) != SX_OK) {
		s->failed = true;
	}
}

static MLD_INLINE void cracen_mldsa_shake_finalize(struct cracen_mldsa_shake_state *s)
{
	if (s->failed || !s->initialized) {
		s->failed = true;
		return;
	}
	if (sx_xof_finalize(&s->xof) != SX_OK) {
		s->failed = true;
	}
}

static MLD_INLINE void cracen_mldsa_shake_squeeze(uint8_t *out, size_t outlen,
						  struct cracen_mldsa_shake_state *s)
{
	if (s->failed || !s->initialized) {
		memset(out, 0, outlen);
		return;
	}
	if (sx_xof_squeeze(&s->xof, out, outlen) != SX_OK) {
		s->failed = true;
		memset(out, 0, outlen);
	}
}

static MLD_INLINE void cracen_mldsa_shake_release(struct cracen_mldsa_shake_state *s)
{
	if (s->initialized) {
		sx_xof_release(&s->xof);
	}
	s->initialized = false;
	s->failed = false;
}

/* The mld_shake{128,256}_* names are macros that resolve to
 * cracen_mldsa_shake{128,256}_* via MLD_NAMESPACE(). We can't define
 * functions called mld_shake256_init directly here because the macro
 * would mangle the declarator; instead we name the functions through
 * the macro so the linker sees cracen_mldsa_shake256_init. */
#define mld_shake128_init MLD_NAMESPACE(shake128_init)
static MLD_INLINE void mld_shake128_init(mld_shake128ctx *state)
{
	cracen_mldsa_shake_init(state, &sxhashalg_shake128);
}

#define mld_shake128_absorb MLD_NAMESPACE(shake128_absorb)
static MLD_INLINE void mld_shake128_absorb(mld_shake128ctx *state, const uint8_t *in,
					   size_t inlen)
{
	cracen_mldsa_shake_absorb(state, in, inlen);
}

#define mld_shake128_finalize MLD_NAMESPACE(shake128_finalize)
static MLD_INLINE void mld_shake128_finalize(mld_shake128ctx *state)
{
	cracen_mldsa_shake_finalize(state);
}

#define mld_shake128_squeeze MLD_NAMESPACE(shake128_squeeze)
static MLD_INLINE void mld_shake128_squeeze(uint8_t *out, size_t outlen,
					    mld_shake128ctx *state)
{
	cracen_mldsa_shake_squeeze(out, outlen, state);
}

#define mld_shake128_release MLD_NAMESPACE(shake128_release)
static MLD_INLINE void mld_shake128_release(mld_shake128ctx *state)
{
	cracen_mldsa_shake_release(state);
}

#define mld_shake256_init MLD_NAMESPACE(shake256_init)
static MLD_INLINE void mld_shake256_init(mld_shake256ctx *state)
{
	cracen_mldsa_shake_init(state, &sxhashalg_shake256);
}

#define mld_shake256_absorb MLD_NAMESPACE(shake256_absorb)
static MLD_INLINE void mld_shake256_absorb(mld_shake256ctx *state, const uint8_t *in,
					   size_t inlen)
{
	cracen_mldsa_shake_absorb(state, in, inlen);
}

#define mld_shake256_finalize MLD_NAMESPACE(shake256_finalize)
static MLD_INLINE void mld_shake256_finalize(mld_shake256ctx *state)
{
	cracen_mldsa_shake_finalize(state);
}

#define mld_shake256_squeeze MLD_NAMESPACE(shake256_squeeze)
static MLD_INLINE void mld_shake256_squeeze(uint8_t *out, size_t outlen,
					    mld_shake256ctx *state)
{
	cracen_mldsa_shake_squeeze(out, outlen, state);
}

#define mld_shake256_release MLD_NAMESPACE(shake256_release)
static MLD_INLINE void mld_shake256_release(mld_shake256ctx *state)
{
	cracen_mldsa_shake_release(state);
}

/* One-shot SHAKE-256: SHAKE256(in, inlen) -> out[0 .. outlen-1]. */
#define mld_shake256 MLD_NAMESPACE(shake256)
static MLD_INLINE void mld_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
				    size_t inlen)
{
	mld_shake256ctx s;

	mld_shake256_init(&s);
	mld_shake256_absorb(&s, in, inlen);
	mld_shake256_finalize(&s);
	mld_shake256_squeeze(out, outlen, &s);
	mld_shake256_release(&s);
}

#endif /* CRACEN_MLDSA_FIPS202_SHIM_H */
