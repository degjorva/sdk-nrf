/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Step 5 — Block erase-all via UICR.ERASEPROTECT.
 *
 * Hardware background (nRF54LV10A):
 *   UICR.ERASEPROTECT register pair (Secure address space only):
 *     NRF_UICR_S->ERASEPROTECT[0].PROTECT0  @ 0xFFD060  (reset: 0xFFFFFFFF)
 *     NRF_UICR_S->ERASEPROTECT[0].PROTECT1  @ 0xFFD07C  (reset: 0xFFFFFFFF)
 *
 *   Valid states:
 *     0xFFFFFFFF / 0xFFFFFFFF — protection NOT active (erase-all allowed)
 *     0x50FA50FA / 0x50FA50FA — protection active (erase-all blocked)
 *
 *   Any other value is suspicious and logged as an error.
 *
 * Limitation — NS world cannot access UICR:
 *   UICR is mapped only in the Secure address space (0xFFD000).
 *   A TF-M non-secure application cannot read or write UICR directly.
 *
 *   TODO: Implement a TF-M platform service (or extend an existing one) that:
 *     1. Reads UICR.ERASEPROTECT.PROTECT0/PROTECT1 and returns them to NS.
 *     2. When activated, writes 0x50FA50FA to both registers.
 *
 *   Prototype for the Secure-side service functions:
 *
 *     int platform_svc_eraseprotect_read(uint32_t *protect0, uint32_t *protect1);
 *     int platform_svc_eraseprotect_activate(void);
 *
 *   On the Secure side, the write uses nrfx_rramc_otp_word_write() or direct
 *   MMIO, similar to how bl_storage writes OTP fields.
 *
 * Runtime TAMPC protection:
 *   In addition to the UICR OTP register, the TAMPC peripheral has a
 *   PROTECT.ERASEPROTECT.CTRL register that can assert protection at runtime:
 *     NRF_TAMPC->PROTECT.ERASEPROTECT.CTRL =
 *         (TAMPC_PROTECT_ERASEPROTECT_CTRL_KEY_KEY << 16) |
 *         (TAMPC_PROTECT_ERASEPROTECT_CTRL_VALUE_High);
 *   This is also Secure-only. If UICR programming is not an option, runtime
 *   TAMPC protection is an alternative. Document which mechanism you intend
 *   to use in your product.
 */

#include "erase_protection.h"
#include "mfg_log.h"
#include "recovery.h"

#include <autoconf.h>

#define ERASEPROTECT_ACTIVE_VALUE   0x50FA50FAU
#define ERASEPROTECT_INACTIVE_VALUE 0xFFFFFFFFU

/* ---------------------------------------------------------------------------
 * Stub for Secure-side UICR read.
 * Replace with a real TF-M platform service call.
 * ---------------------------------------------------------------------------
 */
static int platform_svc_eraseprotect_read(uint32_t *protect0, uint32_t *protect1)
{
	/*
	 * TODO: Implement a TF-M platform IPC call that reads:
	 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT0
	 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT1
	 * and returns them to the NS caller.
	 */
	*protect0 = ERASEPROTECT_INACTIVE_VALUE; /* stub: assume inactive */
	*protect1 = ERASEPROTECT_INACTIVE_VALUE;
	return -ENOSYS; /* -ENOSYS indicates stub — not yet implemented */
}

/* ---------------------------------------------------------------------------
 * Stub for Secure-side UICR write.
 * Replace with a real TF-M platform service call.
 * ---------------------------------------------------------------------------
 */
static int platform_svc_eraseprotect_activate(void)
{
	/*
	 * TODO: Implement a TF-M platform IPC call that writes:
	 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT0 = 0x50FA50FA
	 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT1 = 0x50FA50FA
	 *
	 * On the Secure side this is a one-time OTP write (RRAMC word write).
	 * The write must be verified by reading back the values.
	 */
	return -ENOSYS;
}

/* ---------------------------------------------------------------------------
 * Step 5 entry point
 * ---------------------------------------------------------------------------
 */
void erase_step5_block_if_needed(void)
{
	MFG_LOG_STEP("Checking erase-all policy");

#ifdef CONFIG_BLOCK_ERASE_ALL
	MFG_LOG_INF("CONFIG_BLOCK_ERASE_ALL is active\n");
#else
	MFG_LOG_INF("CONFIG_BLOCK_ERASE_ALL is not active\n");
#endif

	uint32_t protect0 = 0;
	uint32_t protect1 = 0;
	int err = platform_svc_eraseprotect_read(&protect0, &protect1);

	if (err == -ENOSYS) {
		MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT0 = <unavailable from NS>\n");
		MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT1 = <unavailable from NS>\n");
		MFG_LOG_INF("[STUB] UICR read not yet implemented — platform service needed.\n");
		MFG_LOG_INF("       See src/erase_protection.c for integration details.\n");
		return;
	}

	if (err != 0) {
		MFG_LOG_ERR("Failed to read UICR.ERASEPROTECT (err=%d).\n", err);
		recovery_suspend(false);
	}

	MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT0 = 0x%08X\n", protect0);
	MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT1 = 0x%08X\n", protect1);

	bool p0_active   = (protect0 == ERASEPROTECT_ACTIVE_VALUE);
	bool p1_active   = (protect1 == ERASEPROTECT_ACTIVE_VALUE);
	bool p0_inactive = (protect0 == ERASEPROTECT_INACTIVE_VALUE);
	bool p1_inactive = (protect1 == ERASEPROTECT_INACTIVE_VALUE);
	bool p0_valid    = p0_active || p0_inactive;
	bool p1_valid    = p1_active || p1_inactive;

	/* ----- Suspicious values ----- */
	if (!p0_valid || !p1_valid) {
		MFG_LOG_ERR("\nThis is suspicious — UICR.ERASEPROTECT.PROTECT0 and "
			    "UICR.ERASEPROTECT.PROTECT1\n");
		MFG_LOG_ERR("shall be equal to 0xFFFFFFFF.\n");
		recovery_suspend(false);
	}

	bool currently_active = p0_active && p1_active;

#ifdef CONFIG_BLOCK_ERASE_ALL

	if (currently_active) {
		MFG_LOG_INF("erase-all is blocked in UICR, nothing to do.\n");
		return;
	}

	MFG_LOG_INF("\nBlocking erase-all...\n");

	err = platform_svc_eraseprotect_activate();
	if (err != 0) {
		MFG_LOG_ERR("Failed to activate ERASEPROTECT (err=%d).\n", err);
		recovery_suspend(false);
	}

	MFG_LOG_INF("Verifying erase-all...\n");

	err = platform_svc_eraseprotect_read(&protect0, &protect1);
	if (err != 0) {
		MFG_LOG_ERR("Failed to re-read UICR.ERASEPROTECT after write (err=%d).\n", err);
		recovery_suspend(false);
	}

	MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT0 = 0x%08X\n", protect0);
	MFG_LOG_INF("UICR.ERASEPROTECT.PROTECT1 = 0x%08X\n", protect1);

	if (protect0 != ERASEPROTECT_ACTIVE_VALUE || protect1 != ERASEPROTECT_ACTIVE_VALUE) {
		MFG_LOG_ERR("\nSome failures occurred while updating the UICR content.\n");
		recovery_suspend(false);
	}

	MFG_LOG_INF("\nerase-all is successfully blocked in UICR.\n");

#else /* CONFIG_BLOCK_ERASE_ALL not set */

	if (!currently_active) {
		MFG_LOG_INF("erase-all is not blocked in UICR, nothing to do.\n");
		MFG_LOG_INF("\nNotice that the device is not protected against erase all.\n");
		MFG_LOG_INF("Anyone having access to SWD port would be able to wipe out RRAM content.\n");
		MFG_LOG_INF("It would be expected behaviour for engineering devices, but questionable "
			    "for end-devices.\n");
		MFG_LOG_INF("Checking manufacturing flow on engineering devices — "
			    "is it your intention?\n");
	} else {
		MFG_LOG_INF("erase-all is blocked in UICR.\n");
	}

#endif /* CONFIG_BLOCK_ERASE_ALL */
}
