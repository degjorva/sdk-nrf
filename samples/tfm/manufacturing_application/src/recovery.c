/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "recovery.h"
#include "mfg_log.h"

#include <zephyr/kernel.h>

/*
 * Determining erase-all availability from a TF-M non-secure application
 * requires reading UICR.ERASEPROTECT, which is a Secure-mode-only register
 * (mapped at 0xFFD060 in Secure address space only).
 *
 * TODO: Implement a TF-M platform service call (or extend an existing one)
 * that reads UICR.ERASEPROTECT.PROTECT0/PROTECT1 and returns the protection
 * status. Until that service exists, this module conservatively reports
 * erase-all as "status unknown" and logs a note for the operator.
 *
 * Reference registers (nRF54LV10A, Secure access only):
 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT0  @ 0xFFD060
 *   NRF_UICR_S->ERASEPROTECT[0].PROTECT1  @ 0xFFD07C
 *   Protected value: 0x50FA50FA
 *   Unprotected (reset) value: 0xFFFFFFFF
 */

static void log_erase_all_status(void)
{
	/*
	 * TODO: Replace this stub with a TF-M platform service call that
	 * returns the UICR.ERASEPROTECT state. Prototype:
	 *
	 *   bool erase_all_blocked = platform_svc_eraseprotect_is_active();
	 *
	 * Then conditionally print one of:
	 *   Erase-all: available (unblocked)
	 *   Erase-all: unavailable (blocked)
	 */
	MFG_LOG_INF("Erase-all: status unknown (requires Secure-mode platform service)\n");
}

static void log_auth_erase_all_status(bool keys_provisioned)
{
	if (keys_provisioned) {
		MFG_LOG_INF("Authenticated erase-all: available\n");
	} else {
		MFG_LOG_INF("Authenticated erase-all: unavailable (keys are not provisioned yet)\n");
	}
}

__attribute__((noreturn))
void recovery_suspend(bool keys_provisioned)
{
	MFG_LOG_INF("\nTry to recover the device.\n");
	log_erase_all_status();
	log_auth_erase_all_status(keys_provisioned);
	MFG_LOG_INF("Execution suspended.\n");

	/* Infinite loop — the device must be reset externally. */
	while (1) {
		k_sleep(K_MSEC(1000));
	}

	/* Unreachable, but required for __attribute__((noreturn)). */
	CODE_UNREACHABLE;
}
