/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Steps 1, 6, 11 — Lifecycle State (LCS) operations.
 *
 * Reading LCS:
 *   psa_rot_lifecycle_state() is the standard PSA API for reading the current
 *   PRoT security lifecycle state. It is available from TF-M non-secure
 *   context through the TF-M NS interface (psa/lifecycle.h).
 *
 * Advancing LCS:
 *   There is no standard PSA API for advancing the lifecycle state from NS.
 *   On Nordic devices the LCS is stored in OTP (bl_storage) and is written
 *   by bl_storage's update_life_cycle_state(). That function accesses Secure
 *   flash directly and cannot be called from the NS world.
 *
 *   TODO: Implement or call a TF-M platform service that exposes LCS
 *   advancement. Options:
 *     a) Extend the Nordic TF-M platform partition with a new IPC request
 *        type (e.g. TFM_PLATFORM_NRF_ADVANCE_LCS) that calls
 *        update_life_cycle_state() on the Secure side.
 *     b) Use tfm_platform_nv_counter_* or a vendor PSA extension if one is
 *        added in a future NCS release.
 *
 *   Until the platform service is implemented, lcs_advance() logs what it
 *   would do and returns success so that the rest of the manufacturing flow
 *   can be exercised during development.
 */

#include "lcs.h"
#include "mfg_log.h"
#include "recovery.h"

#include <psa/lifecycle.h>

/* ---------------------------------------------------------------------------
 * Name strings matching the spec's human-readable LCS labels.
 * ---------------------------------------------------------------------------
 */
static const char *lcs_name(uint32_t state)
{
	switch (state & PSA_LIFECYCLE_PSA_STATE_MASK) {
	case PSA_LIFECYCLE_ASSEMBLY_AND_TEST:
		return "Manufacturing and Test";
	case PSA_LIFECYCLE_PSA_ROT_PROVISIONING:
		return "PROT Provisioning";
	case PSA_LIFECYCLE_SECURED:
		return "Secured";
	case PSA_LIFECYCLE_DECOMMISSIONED:
		return "Decommissioned";
	default:
		return "Invalid";
	}
}

/* ---------------------------------------------------------------------------
 * LCS advancement stub — replace with a real TF-M platform service call.
 * ---------------------------------------------------------------------------
 */
static int lcs_advance(uint32_t target_psa_state)
{
	/*
	 * TODO: Call a TF-M platform service to advance the LCS.
	 *
	 * Pseudocode for the platform service call:
	 *
	 *   enum lcs target;
	 *   if (target_psa_state == PSA_LIFECYCLE_PSA_ROT_PROVISIONING) {
	 *       target = BL_STORAGE_LCS_PROVISIONING;
	 *   } else if (target_psa_state == PSA_LIFECYCLE_SECURED) {
	 *       target = BL_STORAGE_LCS_SECURED;
	 *   } else {
	 *       return -EINVAL;
	 *   }
	 *   return platform_svc_update_life_cycle_state(target);
	 *
	 * On the Secure side the platform service would call:
	 *   int err = update_life_cycle_state(target);  // from bl_storage.h
	 *
	 * Return 0 on success, non-zero on failure.
	 */
	MFG_LOG_INF("  [STUB] LCS advance to %s — platform service not yet implemented.\n",
		    lcs_name(target_psa_state));
	MFG_LOG_INF("  [STUB] In production, replace this stub with a TF-M platform service call.\n");

	return 0;
}

/* ---------------------------------------------------------------------------
 * Step 1
 * ---------------------------------------------------------------------------
 */
uint32_t lcs_step1_show(void)
{
	MFG_LOG_STEP("Checking LCS");

	uint32_t state = psa_rot_lifecycle_state();

	MFG_LOG_INF("Current LCS = '%s'\n", lcs_name(state));

	uint32_t psa_state = state & PSA_LIFECYCLE_PSA_STATE_MASK;

	if (psa_state == PSA_LIFECYCLE_ASSEMBLY_AND_TEST ||
	    psa_state == PSA_LIFECYCLE_PSA_ROT_PROVISIONING) {
		return state;
	}

	/* Any other LCS indicates a defect in the 2nd-stage bootloader. */
	MFG_LOG_ERR("\nManufacturing application shall not be executed in that state.\n");
	MFG_LOG_ERR("Situation like this indicates a serious defect in 2nd stage bootloader.\n");

	recovery_suspend(false);
}

/* ---------------------------------------------------------------------------
 * Step 6
 * ---------------------------------------------------------------------------
 */
void lcs_step6_advance_to_prot_provisioning(void)
{
	MFG_LOG_STEP("Transition of LCS to 'PROT Provisioning'");

	uint32_t state     = psa_rot_lifecycle_state();
	uint32_t psa_state = state & PSA_LIFECYCLE_PSA_STATE_MASK;

	if (psa_state == PSA_LIFECYCLE_PSA_ROT_PROVISIONING) {
		MFG_LOG_INF("Current LCS = 'PROT Provisioning', no transition needed.\n");
		return;
	}

	MFG_LOG_INF("Current LCS = 'Manufacturing and Test', "
		    "transitioning to 'PROT Provisioning'...\n");

	int err = lcs_advance(PSA_LIFECYCLE_PSA_ROT_PROVISIONING);

	if (err != 0) {
		MFG_LOG_ERR("LCS transition failed (err=%d).\n", err);
		recovery_suspend(true);
	}

	MFG_LOG_INF("Verifying LCS...\n");

	state     = psa_rot_lifecycle_state();
	psa_state = state & PSA_LIFECYCLE_PSA_STATE_MASK;

	MFG_LOG_INF("Current LCS = '%s'\n", lcs_name(state));

	if (psa_state != PSA_LIFECYCLE_PSA_ROT_PROVISIONING) {
		MFG_LOG_ERR("\nSome failures occurred while changing the LCS.\n");
		recovery_suspend(true);
	}
}

/* ---------------------------------------------------------------------------
 * Step 11
 * ---------------------------------------------------------------------------
 */
void lcs_step11_advance_to_secured(void)
{
	MFG_LOG_STEP("Transition of LCS to 'Secured'");

	uint32_t state     = psa_rot_lifecycle_state();
	uint32_t psa_state = state & PSA_LIFECYCLE_PSA_STATE_MASK;

	if (psa_state != PSA_LIFECYCLE_PSA_ROT_PROVISIONING) {
		MFG_LOG_ERR("Current LCS = '%s'\n\n", lcs_name(state));
		MFG_LOG_ERR("There must be a defect in the device or the application.\n");
		recovery_suspend(true);
	}

	MFG_LOG_INF("Current LCS = 'PROT Provisioning', transitioning to 'Secured'...\n");

	int err = lcs_advance(PSA_LIFECYCLE_SECURED);

	if (err != 0) {
		MFG_LOG_ERR("LCS transition failed (err=%d).\n", err);
		recovery_suspend(true);
	}

	MFG_LOG_INF("Verifying LCS...\n");

	state     = psa_rot_lifecycle_state();
	psa_state = state & PSA_LIFECYCLE_PSA_STATE_MASK;

	MFG_LOG_INF("Current LCS = '%s'\n", lcs_name(state));

	if (psa_state != PSA_LIFECYCLE_SECURED) {
		MFG_LOG_ERR("\nSome failures occurred while changing the LCS.\n");
		recovery_suspend(true);
	}
}
