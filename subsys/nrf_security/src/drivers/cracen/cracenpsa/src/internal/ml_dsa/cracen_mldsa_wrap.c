/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Single compilation unit that builds mldsa-native once per enabled
 * parameter set. Modelled on
 * modules/crypto/mldsa-native/examples/monolithic_build_multilevel/
 * and the pqcp wrapper in
 * modules/crypto/tf-psa-crypto/drivers/pqcp/src/wrap_mldsa_native.c.
 *
 * Per the mldsa-native multi-level build contract:
 *   - exactly one enabled level is compiled with
 *     MLD_CONFIG_MULTILEVEL_WITH_SHARED so the parameter-set-independent
 *     code (NTT zetas, packing, etc.) is emitted exactly once;
 *   - all other enabled levels are compiled with
 *     MLD_CONFIG_MULTILEVEL_NO_SHARED;
 *   - MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS is defined for every
 *     include except the very last enabled level, where it is left
 *     undefined so the SCU undef's the shared headers at the end.
 *
 * We pick the lowest enabled level as the "shared" owner and the
 * highest enabled level as the "last" include. Both are determined
 * purely from CONFIG_PSA_NEED_CRACEN_ML_DSA_{44,65,87}.
 */

#define MLD_CONFIG_FILE "cracen_mldsa_config.h"

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
#define CRACEN_MLDSA_LAST_LEVEL 87
#elif defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
#define CRACEN_MLDSA_LAST_LEVEL 65
#elif defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
#define CRACEN_MLDSA_LAST_LEVEL 44
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
#define CRACEN_MLDSA_FIRST_LEVEL 44
#elif defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
#define CRACEN_MLDSA_FIRST_LEVEL 65
#elif defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
#define CRACEN_MLDSA_FIRST_LEVEL 87
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
#define MLD_CONFIG_PARAMETER_SET 44
#if CRACEN_MLDSA_FIRST_LEVEL == 44
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#else
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
#if CRACEN_MLDSA_LAST_LEVEL != 44
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#endif
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#ifdef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#endif
#ifdef MLD_CONFIG_MULTILEVEL_NO_SHARED
#undef MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
#ifdef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#endif
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
#define MLD_CONFIG_PARAMETER_SET 65
#if CRACEN_MLDSA_FIRST_LEVEL == 65
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#else
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
#if CRACEN_MLDSA_LAST_LEVEL != 65
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#endif
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#ifdef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#endif
#ifdef MLD_CONFIG_MULTILEVEL_NO_SHARED
#undef MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
#ifdef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#endif
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
#define MLD_CONFIG_PARAMETER_SET 87
#if CRACEN_MLDSA_FIRST_LEVEL == 87
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#else
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
/* 87 is always the last enabled level if it is enabled, so we never
 * define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS here -- the SCU will
 * undef the shared headers when it finishes. */
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#ifdef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#endif
#ifdef MLD_CONFIG_MULTILEVEL_NO_SHARED
#undef MLD_CONFIG_MULTILEVEL_NO_SHARED
#endif
#endif
