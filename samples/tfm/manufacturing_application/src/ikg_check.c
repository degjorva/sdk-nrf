/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Step 2 — Validate that no IKG seed or KeyRAM random data is already present.
 *
 * Check strategy (from a TF-M non-secure context):
 *
 * IKG seed presence:
 *   The IKG seed is stored in KMU with CRACEN_KMU_KEY_USAGE_SCHEME_SEED.
 *   When the seed is present, CRACEN can derive the Initial Attestation Key
 *   (IAK, ID = CRACEN_BUILTIN_IDENTITY_KEY_ID = 0x7FFFC001).
 *   We attempt psa_export_public_key() on the IAK:
 *     - PSA_SUCCESS                → seed IS present (error — must suspend).
 *     - PSA_ERROR_DOES_NOT_EXIST   → seed not present (good).
 *     - Other error                → inconclusive; logged and treated as error.
 *
 * KeyRAM random slots (PROTECTED_RAM_INVALIDATION_DATA_SLOT1 = 248,
 *                      PROTECTED_RAM_INVALIDATION_DATA_SLOT2 = 249):
 *   We attempt psa_get_key_attributes() on the PSA key ID that maps to each
 *   slot:
 *     - PSA_SUCCESS                → slot occupied (error — must suspend).
 *     - PSA_ERROR_INVALID_HANDLE   → slot empty (good).
 *     - PSA_ERROR_DOES_NOT_EXIST   → slot empty (good).
 */

#include "ikg_check.h"
#include "mfg_log.h"
#include "recovery.h"

#include <psa/crypto.h>
#include <cracen_psa_kmu.h>
#include <cracen_psa_key_ids.h>

/* ---------------------------------------------------------------------------
 * IKG seed presence check via IAK derivability
 * ---------------------------------------------------------------------------
 */
static void check_ikg_seed_slots(void)
{
	MFG_LOG_INF("Verifying KMU IKG seed slots...");

	uint8_t pub_key_buf[32]; /* Ed25519 public key, 32 bytes */
	size_t  pub_key_len = 0;

	mbedtls_svc_key_id_t iak_id =
		mbedtls_svc_key_id_make(0, CRACEN_BUILTIN_IDENTITY_KEY_ID);

	psa_status_t status = psa_export_public_key(iak_id,
						    pub_key_buf, sizeof(pub_key_buf),
						    &pub_key_len);

	if (status == PSA_ERROR_DOES_NOT_EXIST || status == PSA_ERROR_INVALID_HANDLE) {
		MFG_LOG_INF(" OK (empty)\n");
		return;
	}

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF(" FAIL (not empty)\n");
		MFG_LOG_ERR("\nSeems IKG seed is already provisioned. Secrecy and entropy level\n");
		MFG_LOG_ERR("of that data cannot be trusted.\n");
		recovery_suspend(false);
	}

	/* Any other error is inconclusive — treat as failure for safety. */
	MFG_LOG_INF(" FAIL (psa_export_public_key returned %d — inconclusive)\n", status);
	MFG_LOG_ERR("\nCould not determine IKG seed slot state. Halting for safety.\n");
	recovery_suspend(false);
}

/* ---------------------------------------------------------------------------
 * KeyRAM random slot presence check
 *
 * Slot numbers are defined in cracen_kmu.h:
 *   PROTECTED_RAM_INVALIDATION_DATA_SLOT1 = 248
 *   PROTECTED_RAM_INVALIDATION_DATA_SLOT2 = 249
 * ---------------------------------------------------------------------------
 */
static void check_one_keyram_slot(int slot_id)
{
	MFG_LOG_INF("Verifying KMU KeyRAM random slot %d...", slot_id);

	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED, slot_id);

	mbedtls_svc_key_id_t svc_key_id = mbedtls_svc_key_id_make(0, key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(svc_key_id, &attr);

	psa_reset_key_attributes(&attr);

	if (status == PSA_ERROR_INVALID_HANDLE || status == PSA_ERROR_DOES_NOT_EXIST) {
		MFG_LOG_INF(" OK (empty)\n");
		return;
	}

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF(" FAIL (not empty)\n");
		MFG_LOG_ERR("\nSeems KeyRAM random (slot %d) is already provisioned.\n", slot_id);
		MFG_LOG_ERR("Secrecy and entropy level of that data cannot be trusted.\n");
		recovery_suspend(false);
	}

	MFG_LOG_INF(" FAIL (psa_get_key_attributes returned %d — inconclusive)\n", status);
	MFG_LOG_ERR("\nCould not determine KeyRAM random slot %d state. Halting for safety.\n",
		    slot_id);
	recovery_suspend(false);
}

/* ---------------------------------------------------------------------------
 * Step 2 entry point
 * ---------------------------------------------------------------------------
 */
void ikg_step2_check_empty(void)
{
	MFG_LOG_STEP("Checking IKG seed presence");

	check_ikg_seed_slots();

	check_one_keyram_slot(PROTECTED_RAM_INVALIDATION_DATA_SLOT1);
	check_one_keyram_slot(PROTECTED_RAM_INVALIDATION_DATA_SLOT2);
}
