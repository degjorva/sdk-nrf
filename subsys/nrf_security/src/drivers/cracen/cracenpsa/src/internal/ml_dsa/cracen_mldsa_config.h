/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * mldsa-native configuration used by the CRACEN PSA driver.
 *
 * This file is referenced from the CRACEN PSA driver by passing
 * -DMLD_CONFIG_FILE="cracen_mldsa_config.h" when compiling both
 * cracen_mldsa_wrap.c (the SCU that builds mldsa-native) and any
 * translation unit that includes cracen_mldsa_wrap.h.
 *
 * The configuration intentionally:
 *   - leaves MLD_CONFIG_PARAMETER_SET unset so the wrappers can
 *     compile mldsa-native once per enabled level (44/65/87);
 *   - swaps mldsa-native's FIPS-202 backend for a shim over CRACEN's
 *     sx_xof_* streaming SHAKE API (MLD_CONFIG_FIPS202_CUSTOM_HEADER);
 *   - forces serial Keccak operation (MLD_CONFIG_SERIAL_FIPS202_ONLY)
 *     because the BA418 holds only a single Keccak state;
 *   - prefers the RAM-reduced data layout suitable for nRF54L-class
 *     parts (MLD_CONFIG_REDUCE_RAM); and
 *   - drops randomized entry points and SUPERCOP names that the PSA
 *     driver does not use.
 */

#ifndef CRACEN_MLDSA_CONFIG_H
#define CRACEN_MLDSA_CONFIG_H

/* Multilevel build: each enabled parameter set is selected externally
 * via MLD_CONFIG_PARAMETER_SET. Do not set it here. */
#define MLD_CONFIG_MULTILEVEL_BUILD

/* Namespace all global mldsa-native symbols as cracen_mldsa{44,65,87}_*. */
#define MLD_CONFIG_NAMESPACE_PREFIX cracen_mldsa

/* The randomized API is not used by the verify-only driver; rejecting it
 * also lets us avoid pulling in a randombytes() symbol. */
#define MLD_CONFIG_NO_RANDOMIZED_API

/* No need for the SUPERCOP crypto_sign_* aliases. Required for multilevel. */
#define MLD_CONFIG_NO_SUPERCOP

/* Mark internal mldsa-native functions static so the compiler can drop
 * unused entry points (we only consume verify_internal /
 * prepare_domain_separation_prefix in v1). */
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static

/* Use mbedtls_platform_zeroize for stack scrubbing so we don't pull in
 * mldsa-native's inline-asm implementation on Cortex-M. */
#define MLD_CONFIG_CUSTOM_ZEROIZE
#ifndef __ASSEMBLER__
#include <mbedtls/platform_util.h>
static inline void mld_zeroize(void *ptr, size_t len)
{
	mbedtls_platform_zeroize(ptr, len);
}
#endif

/* Route Keccak through the CRACEN sx_xof_* API. */
#define MLD_CONFIG_FIPS202_CUSTOM_HEADER "cracen_mldsa_fips202_shim.h"

/* BA418 has a single Keccak state, so mldsa-native must never have more
 * than one active SHAKE context. With this flag set, the x4 batched
 * fips202 header is not included, so we do not need to provide an x4
 * shim. */
#define MLD_CONFIG_SERIAL_FIPS202_ONLY

/* Trade some performance for a much smaller working set. This drops
 * ML-DSA-87 verify from ~99 KB to ~41 KB of MLD_TOTAL_ALLOC (see
 * mldsa-native/mldsa/mldsa_native.h). */
#define MLD_CONFIG_REDUCE_RAM

#endif /* CRACEN_MLDSA_CONFIG_H */
