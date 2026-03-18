/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file image_validation.h
 *
 * Step 3 — Validate digests of all sub-images in the initial image.
 */

#ifndef IMAGE_VALIDATION_H_
#define IMAGE_VALIDATION_H_

/**
 * @brief Step 3 — Validate all sub-image digests.
 *
 * Checks SHA-256 digests of:
 *   - BL1 (expected digest injected at build time via -DMFG_BL1_DIGEST=...)
 *   - BL2, slot A (expected digest injected at build time)
 *   - BL2, slot B (expected digest injected at build time)
 *   - Manufacturing application (reads its own MCUboot TLV at runtime)
 *   - Application candidate (expected digest injected at build time)
 *
 * Suspends execution if any verification fails.
 *
 * @note BL1 and BL2 reside in Secure flash and cannot be read directly from
 *       a TF-M non-secure application. Their validation is currently stubbed.
 *       See image_validation.c for integration details.
 */
void image_step3_validate_all(void);

#endif /* IMAGE_VALIDATION_H_ */
