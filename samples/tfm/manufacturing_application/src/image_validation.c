/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Step 3 — Image digest validation.
 *
 * Sub-image accessibility from a TF-M non-secure application:
 *
 * BL1:
 *   Resides in the Secure flash region. The NS application cannot read it
 *   directly. Validation requires either:
 *     a) A TF-M platform service that hashes a given Secure flash range and
 *        returns the digest to the NS caller.
 *     b) Having BL1 validate itself and expose the result via a platform call.
 *   TODO: Implement one of the options above. Currently stubbed.
 *
 * BL2 (MCUboot), slot A and slot B:
 *   MCUboot also resides in Secure flash (boot_partition at offset 0x000000).
 *   Same limitation as BL1 applies.
 *   TODO: Implement a TF-M platform service for Secure flash hashing.
 *
 * Manufacturing application (self-validation):
 *   The manufacturing app is an MCUboot-compatible image stored in the NS
 *   flash partition (slot0_ns_partition). Its SHA-256 hash is stored in the
 *   MCUboot image TLV (Type-Length-Value trailer). The NS app can:
 *     1. Read the MCUboot header to find the image size.
 *     2. Hash the image body using psa_hash_compute().
 *     3. Read the expected hash from the TLV and compare.
 *   This is possible because the NS app has read access to its own flash
 *   partition via the FLASH_MAP API.
 *   TODO: Implement TLV parsing and self-hash. Currently stubbed due to
 *   dependency on MCUboot TLV layout headers.
 *
 * Application candidate:
 *   Stored in slot1_ns_partition (NS flash, readable by the NS app). The
 *   expected digest is injected at build time via -DMFG_APP_CANDIDATE_DIGEST.
 *   TODO: Implement flash-map read and PSA hash comparison.
 */

#include "image_validation.h"
#include "mfg_log.h"
#include "recovery.h"

#include <psa/crypto.h>
#include <image_digests.h>

/* ---------------------------------------------------------------------------
 * Digest comparison helper
 * ---------------------------------------------------------------------------
 */
static bool digests_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	/* Constant-time compare to avoid timing side-channels. */
	uint8_t diff = 0;

	for (size_t i = 0; i < len; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff == 0;
}

/* ---------------------------------------------------------------------------
 * BL1 validation (stub — requires Secure flash access via platform service)
 * ---------------------------------------------------------------------------
 */
static void validate_bl1(void)
{
	MFG_LOG_INF("Validating Bootloader 1...");

	if (mfg_digest_is_zero(mfg_bl1_expected_digest)) {
		MFG_LOG_INF(" SKIP (no expected digest provided at build time)\n");
		MFG_LOG_INF("  Provide -DMFG_BL1_DIGEST=<sha256hex> to enable BL1 validation.\n");
		return;
	}

	/*
	 * TODO: Call a TF-M platform service to hash the BL1 flash region.
	 *
	 * Pseudocode:
	 *   uint8_t actual[MFG_DIGEST_LEN];
	 *   int err = platform_svc_hash_secure_region(BL1_START, BL1_SIZE, actual);
	 *   if (err != 0 || !digests_equal(actual, mfg_bl1_expected_digest, MFG_DIGEST_LEN)) {
	 *       MFG_LOG_INF(" FAIL (incorrect digest)\n");
	 *       recovery_suspend(false);
	 *   }
	 *   MFG_LOG_INF(" OK\n");
	 */
	MFG_LOG_INF(" SKIP (BL1 in Secure flash — platform service not yet implemented)\n");
}

/* ---------------------------------------------------------------------------
 * BL2 (MCUboot) slot A validation (stub — requires Secure flash access)
 * ---------------------------------------------------------------------------
 */
static void validate_bl2_slot_a(void)
{
	MFG_LOG_INF("Validating Bootloader 2, slot A...");

	if (mfg_digest_is_zero(mfg_bl2_slot_a_expected_digest)) {
		MFG_LOG_INF(" SKIP (no expected digest provided at build time)\n");
		return;
	}

	/* TODO: Same as BL1 — requires Secure flash hashing platform service. */
	MFG_LOG_INF(" SKIP (BL2 in Secure flash — platform service not yet implemented)\n");
}

/* ---------------------------------------------------------------------------
 * BL2 (MCUboot) slot B validation (stub — requires Secure flash access)
 * ---------------------------------------------------------------------------
 */
static void validate_bl2_slot_b(void)
{
	MFG_LOG_INF("Validating Bootloader 2, slot B...");

	if (mfg_digest_is_zero(mfg_bl2_slot_b_expected_digest)) {
		MFG_LOG_INF(" SKIP (no expected digest provided at build time)\n");
		return;
	}

	/* TODO: Same as BL1 — requires Secure flash hashing platform service. */
	MFG_LOG_INF(" SKIP (BL2 in Secure flash — platform service not yet implemented)\n");
}

/* ---------------------------------------------------------------------------
 * Manufacturing application self-validation
 *
 * The manufacturing app is an MCUboot-compatible NS image. MCUboot signs it
 * and stores the SHA-256 hash in the image TLV. At runtime the app can:
 *   1. Read the MCUboot image header at its own load address to find image_size.
 *   2. Hash bytes [header_size .. header_size + image_size) with PSA SHA-256.
 *   3. Parse the TLV area (after the image body) for the SHA256 TLV entry.
 *   4. Compare the computed hash with the stored hash.
 *
 * This avoids the chicken-and-egg problem because:
 *   - The hash is computed over the image body only (not the TLV).
 *   - The TLV entry containing the expected hash is outside the hashed area.
 *   - imgtool places the hash in the TLV using this exact convention.
 *
 * TODO: Implement TLV parsing. Requires either:
 *   a) Including MCUboot's bootutil/image.h header in the NS application.
 *   b) Implementing a minimal TLV parser for the fields needed.
 * ---------------------------------------------------------------------------
 */
static void validate_manufacturing_app(void)
{
	MFG_LOG_INF("Validating Manufacturing application (self-check)...");

	/*
	 * TODO: Implement self-validation using the MCUboot TLV hash.
	 *
	 * Pseudocode:
	 *
	 *   const struct image_header *hdr =
	 *       (const struct image_header *)PM_MCUBOOT_PRIMARY_NS_ADDRESS;
	 *
	 *   uint8_t computed[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
	 *   size_t  computed_len;
	 *   const uint8_t *image_body = (uint8_t *)hdr + hdr->ih_hdr_size;
	 *
	 *   psa_status_t status = psa_hash_compute(
	 *       PSA_ALG_SHA_256,
	 *       image_body, hdr->ih_img_size,
	 *       computed, sizeof(computed), &computed_len);
	 *
	 *   // Parse TLV for IMAGE_TLV_SHA256 entry and compare.
	 */
	MFG_LOG_INF(" SKIP (TLV parser not yet implemented)\n");
}

/* ---------------------------------------------------------------------------
 * Application candidate validation
 * ---------------------------------------------------------------------------
 */
static void validate_app_candidate(void)
{
	MFG_LOG_INF("Validating Application candidate...");

	if (mfg_digest_is_zero(mfg_app_candidate_expected_digest)) {
		MFG_LOG_INF(" SKIP (no expected digest provided at build time)\n");
		MFG_LOG_INF("  Provide -DMFG_APP_CANDIDATE_DIGEST=<sha256hex> to enable.\n");
		return;
	}

	/*
	 * TODO: Read the application candidate from flash (slot1_ns_partition)
	 * and hash it, then compare against mfg_app_candidate_expected_digest.
	 *
	 * The NS app has read access to its own NS flash partition via
	 * the Zephyr FLASH_MAP / FIXED_PARTITION APIs.
	 *
	 * Pseudocode:
	 *   const struct flash_area *fa;
	 *   flash_area_open(FIXED_PARTITION_ID(slot1_partition), &fa);
	 *
	 *   uint8_t computed[MFG_DIGEST_LEN];
	 *   size_t  computed_len;
	 *   // Read candidate image and hash it with psa_hash_compute().
	 *   // Compare with mfg_app_candidate_expected_digest.
	 */
	MFG_LOG_INF(" SKIP (flash-map read not yet implemented)\n");
}

/* ---------------------------------------------------------------------------
 * Step 3 entry point
 * ---------------------------------------------------------------------------
 */
void image_step3_validate_all(void)
{
	MFG_LOG_STEP("Validating images");

	validate_bl1();
	validate_bl2_slot_a();
	validate_bl2_slot_b();
	validate_manufacturing_app();
	validate_app_candidate();
}
