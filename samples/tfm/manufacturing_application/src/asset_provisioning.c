/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Step 10 — Provision remaining assets and device enrolment (placeholder).
 *
 * At this stage of the manufacturing flow the device is:
 *   - Authenticated (ADAC / secure-boot keys provisioned, Step 4)
 *   - Running with IKG seed and IAK available (Step 8)
 *   - In LCS = 'PROT Provisioning' (Step 6)
 *
 * This makes it safe to:
 *   - Establish a trusted, authenticated secure channel to an external
 *     Device Management or provisioning server (using the IAK for mutual
 *     authentication).
 *   - Enrol the device in a cloud Device Management System (DMS).
 *   - Negotiate or receive additional assets:
 *       * X.509 device certificates
 *       * Symmetric keys for application-level encryption
 *       * Firmware update keys
 *       * Network credentials
 *
 * Security note:
 *   Secure delivery or derivation of private keys and symmetric keys,
 *   while technically feasible using the MKEK/MEXT derivation chain,
 *   is out of scope of this reference application.
 */

#include "asset_provisioning.h"
#include "mfg_log.h"

void assets_step10_provision(void)
{
	MFG_LOG_STEP("Provisioning of remaining assets");

	MFG_LOG_INF("This is a good place to add code for provisioning of other assets.\n");
	MFG_LOG_INF("Manufacturing app is authenticated at that stage, so it is possible to\n");
	MFG_LOG_INF("establish a trusted secure channel to an external system, to enrol the\n");
	MFG_LOG_INF("device to Device Management System, and get/negotiate any other required\n");
	MFG_LOG_INF("assets (i.e. certificates, keys etc.)\n\n");
	MFG_LOG_INF("Secure delivery/derivation of private/symmetric keys, however feasible,\n");
	MFG_LOG_INF("is out of scope of this application.\n");
}
