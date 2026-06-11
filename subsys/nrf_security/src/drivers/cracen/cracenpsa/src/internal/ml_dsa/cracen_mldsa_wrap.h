/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Per-parameter-set declarations of mldsa-native exposed to the CRACEN
 * PSA driver.
 *
 * mldsa-native's public header mldsa_native.h is parameterized on
 * MLD_CONFIG_PARAMETER_SET. To get declarations of all enabled levels
 * in one translation unit we include it once per enabled level,
 * #undef'ing MLD_H between inclusions as documented in
 * mldsa-native/mldsa/mldsa_native.h.
 */

#ifndef CRACEN_MLDSA_WRAP_H
#define CRACEN_MLDSA_WRAP_H

#define MLD_CONFIG_FILE "cracen_mldsa_config.h"

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#endif

#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#endif

#endif /* CRACEN_MLDSA_WRAP_H */
