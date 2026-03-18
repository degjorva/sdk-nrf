/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file lcs.h
 *
 * Lifecycle State (LCS) operations for the manufacturing application.
 *
 * Covers Steps 1, 6, and 11 of the manufacturing flow.
 *
 * LCS reading is performed via psa_rot_lifecycle_state() which is available
 * from TF-M non-secure context through the TF-M NS interface.
 *
 * LCS advancement (writing) requires Secure-mode access and is currently
 * implemented as a stub. See lcs.c for integration details.
 */

#ifndef LCS_H_
#define LCS_H_

#include <stdint.h>

/**
 * @brief Step 1 — Log the current LCS.
 *
 * Reads the current PSA lifecycle state and logs it. If the state is not
 * one of the two valid manufacturing states ('Manufacturing and Test' or
 * 'PROT Provisioning'), logs an error and suspends execution.
 *
 * @return The raw PSA_LIFECYCLE_* value of the current state.
 */
uint32_t lcs_step1_show(void);

/**
 * @brief Step 6 — Advance LCS to 'PROT Provisioning'.
 *
 * If already in 'PROT Provisioning', logs that no transition is needed.
 * If in 'Manufacturing and Test', advances the state and verifies it.
 * On failure, logs an error and suspends execution.
 */
void lcs_step6_advance_to_prot_provisioning(void);

/**
 * @brief Step 11 — Advance LCS to 'Secured'.
 *
 * If not in 'PROT Provisioning', logs an error and suspends execution.
 * Otherwise advances to 'Secured' and verifies the transition.
 */
void lcs_step11_advance_to_secured(void);

#endif /* LCS_H_ */
