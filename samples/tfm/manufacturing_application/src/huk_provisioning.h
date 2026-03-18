/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file huk_provisioning.h
 *
 * Steps 7 and 8 — Provision KeyRAM random data and IKG seed.
 *
 * "KeyRAM random" refers to the protected RAM invalidation slots (KMU slots
 * 248 and 249, defined as PROTECTED_RAM_INVALIDATION_DATA_SLOT1/2 in
 * cracen_kmu.h). These hold random data that CRACEN pushes to its protected
 * RAM to overwrite key material after each use.
 *
 * "IKG seed" is the 384-bit (48-byte) seed for CRACEN's Internal Key
 * Generator. From the seed, CRACEN derives all device-unique keys:
 *   - Initial Attestation Key (IAK) — ID 0x7FFFC001
 *   - Master Key Encryption Key (MKEK) — ID 0x7FFFC002
 *   - Master External Key (MEXT) — ID 0x7FFFC003
 */

#ifndef HUK_PROVISIONING_H_
#define HUK_PROVISIONING_H_

/**
 * @brief Step 7 — Provision KeyRAM random data to KMU slots 248 and 249.
 *
 * If already provisioned, logs that fact and returns. Otherwise generates
 * random data and provisions both slots. Suspends on failure.
 */
void huk_step7_provision_keyram_random(void);

/**
 * @brief Step 8 — Provision the IKG seed and log derived key information.
 *
 * If already provisioned, logs that fact and returns. Otherwise generates
 * and provisions the 384-bit IKG seed. After provisioning, logs the public
 * representation of IAK, MKEK ID, MEXT ID, and PSA Instance ID.
 * Suspends on failure.
 */
void huk_step8_provision_ikg_seed(void);

#endif /* HUK_PROVISIONING_H_ */
