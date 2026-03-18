/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file main.c
 *
 * Manufacturing application — 12-step provisioning flow for nRF54LV10A.
 *
 * Overview
 * --------
 * This application is a reference implementation of the manufacturing flow
 * for Nordic Semiconductor devices using TF-M and CRACEN. It runs as a TF-M
 * non-secure application in the MCUboot slot0_ns partition after the full
 * boot chain (BL1 → BL2/MCUboot → TF-M) has completed.
 *
 * Idempotency
 * -----------
 * The application is designed to be idempotent: every boot executes all
 * 12 steps. Each step checks its own precondition at entry and exits cleanly
 * if the operation has already been performed (e.g. "already provisioned").
 * This makes the application immune to power drops at any point in the flow.
 *
 * Execution flow
 * --------------
 * Step  1: Show LCS at entry — verifies device is in a valid manufacturing state.
 * Step  2: Validate no IKG seed present (in 'Manufacturing and Test' only).
 * Step  3: Validate digests of all sub-images (BL1, BL2, mfg app, app candidate).
 * Step  4: Provision and verify secure-boot and ADAC public keys.
 * Step  5: Block erase-all via UICR.ERASEPROTECT (if CONFIG_BLOCK_ERASE_ALL).
 * Step  6: Advance LCS to 'PROT Provisioning'.
 * Step  7: Provision KeyRAM random data (KMU slots 248, 249).
 * Step  8: Provision IKG seed; log IAK / MKEK / MEXT identifiers.
 * Step  9: End product tests (placeholder — customise for your product).
 * Step 10: Provision remaining assets and device enrolment (placeholder).
 * Step 11: Advance LCS to 'Secured'.
 * Step 12: Revoke manufacturing app key; reboot to install target application.
 *
 * Open questions and stubs
 * ------------------------
 * Several operations require Secure-mode access and are currently implemented
 * as stubs pending the addition of TF-M platform services:
 *   - LCS advancement (steps 6 and 11)
 *   - UICR.ERASEPROTECT read/write (step 5)
 *   - KeyRAM random provisioning (step 7)
 *   - IKG seed provisioning via hw_unique_key_write_random (step 8)
 *   - Image hashing for Secure-side images (step 3)
 *
 * See each step's .c file for TODO comments with detailed integration guidance.
 * A full list of open questions is provided in README.rst.
 *
 * Reference
 * ---------
 * See README.rst for build instructions, key generation, and expected output.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <psa/crypto.h>
#include <psa/lifecycle.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#include "mfg_log.h"
#include "lcs.h"
#include "ikg_check.h"
#include "image_validation.h"
#include "key_provisioning.h"
#include "erase_protection.h"
#include "huk_provisioning.h"
#include "product_tests.h"
#include "asset_provisioning.h"

int main(void)
{
	psa_status_t status;

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		MFG_LOG_ERR("FATAL: psa_crypto_init() failed (%d). "
			    "Cannot continue.\n", status);
		return 0;
	}

	/* ------------------------------------------------------------------ */
	/* Step 1 — Show LCS at entry                                          */
	/* ------------------------------------------------------------------ */
	uint32_t lcs_state = lcs_step1_show();

	/* ------------------------------------------------------------------ */
	/* Step 2 — Validate no IKG seed or KeyRAM random in MTEST LCS        */
	/* Only executed when the device is in 'Manufacturing and Test'.       */
	/* In 'PROT Provisioning' the seed may already be present from a      */
	/* previous (partial) run; Step 2 is skipped to remain idempotent.    */
	/* ------------------------------------------------------------------ */
	if ((lcs_state & PSA_LIFECYCLE_PSA_STATE_MASK) == PSA_LIFECYCLE_ASSEMBLY_AND_TEST) {
		ikg_step2_check_empty();
	}

	/* ------------------------------------------------------------------ */
	/* Step 3 — Check consistency of all images                           */
	/* ------------------------------------------------------------------ */
	image_step3_validate_all();

	/* ------------------------------------------------------------------ */
	/* Step 4 — Provision secure-boot and ADAC keys                       */
	/* ------------------------------------------------------------------ */
	key_step4_provision_all();

	/* ------------------------------------------------------------------ */
	/* Step 5 — Block erase-all (if CONFIG_BLOCK_ERASE_ALL is enabled)    */
	/* ------------------------------------------------------------------ */
	erase_step5_block_if_needed();

	/* ------------------------------------------------------------------ */
	/* Step 6 — Advance LCS to 'PROT Provisioning'                        */
	/* ------------------------------------------------------------------ */
	lcs_step6_advance_to_prot_provisioning();

	/* ------------------------------------------------------------------ */
	/* Step 7 — Provision KeyRAM random data                               */
	/* ------------------------------------------------------------------ */
	huk_step7_provision_keyram_random();

	/* ------------------------------------------------------------------ */
	/* Step 8 — Provision IKG seed                                         */
	/* ------------------------------------------------------------------ */
	huk_step8_provision_ikg_seed();

	/* ------------------------------------------------------------------ */
	/* Step 9 — End product tests                                          */
	/* ------------------------------------------------------------------ */
	tests_step9_run();

	/* ------------------------------------------------------------------ */
	/* Step 10 — Provision remaining assets and device enrolment          */
	/* ------------------------------------------------------------------ */
	assets_step10_provision();

	/* ------------------------------------------------------------------ */
	/* Step 11 — Advance LCS to 'Secured'                                  */
	/* ------------------------------------------------------------------ */
	lcs_step11_advance_to_secured();

	/* ------------------------------------------------------------------ */
	/* Step 12 — Clean up and goodbye                                      */
	/* ------------------------------------------------------------------ */
	MFG_LOG_STEP("Cleaning up");

	key_step12_revoke_mfg_key();

	MFG_LOG_INF("\nManufacturing process is completed. Now the device is about to reboot and\n");
	MFG_LOG_INF("target application will be installed.\n");
	MFG_LOG_INF("\nRebooting the device...\n");

	/* Allow the UART to flush the final log messages before reboot. */
	k_sleep(K_MSEC(100));

	sys_reboot(SYS_REBOOT_COLD);

	return 0;
}
