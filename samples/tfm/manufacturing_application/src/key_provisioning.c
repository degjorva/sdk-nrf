/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Steps 4 and 12 — Key provisioning and revocation.
 *
 * Key provisioning from a TF-M non-secure application:
 *   Keys are imported into KMU slots via psa_import_key() with a key ID
 *   constructed by PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(scheme, slot).
 *   The PSA Crypto layer in TF-M's Secure world executes the actual KMU write
 *   through the CRACEN PSA driver.
 *
 *   Key policy documentation — options for each attribute:
 *
 *   Usage scheme (passed as the first argument to PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT):
 *     CRACEN_KMU_KEY_USAGE_SCHEME_RAW       — not encrypted; pushed to MCU-accessible
 *                                             kmu_push_area for usage. Suitable for
 *                                             Ed25519 / ECDSA public keys.
 *     CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED — pushed to CRACEN's protected RAM only.
 *                                             Only AES is supported in this mode.
 *     CRACEN_KMU_KEY_USAGE_SCHEME_ENCRYPTED — stored encrypted; decrypted to push area.
 *     CRACEN_KMU_KEY_USAGE_SCHEME_SEED      — IKG seed; pushed to CRACEN seed register.
 *
 *   Revocation policy (set via PSA key persistence):
 *     CRACEN_KEY_PERSISTENCE_REVOKABLE (0x02) — once deleted, the slot cannot be
 *                                               re-provisioned. Transition to 'Erased'.
 *     CRACEN_KEY_PERSISTENCE_READ_ONLY  (0x03) — cannot be erased except by ERASEALL.
 *     PSA_KEY_PERSISTENCE_DEFAULT             — key persists across resets; slot can be
 *                                               reused after deletion (ROTATING policy).
 *
 * Detecting a revoked (appears-empty) slot:
 *   A KMU slot that previously held a REVOKABLE key appears empty after revocation
 *   but psa_import_key() will fail without a clear error code. The application
 *   cannot distinguish this case from a hardware fault. This is a known hardware
 *   limitation. The log message "Possible reason — a key was provisioned and
 *   revoked from given KMU slot" is the best achievable diagnostic.
 */

#include "key_provisioning.h"
#include "mfg_log.h"
#include "recovery.h"

#include <zephyr/kernel.h>
#include <psa/crypto.h>
#include <cracen_psa_kmu.h>
#include <cracen_psa_key_ids.h>

#include <provisioned_keys.h>

/* ---------------------------------------------------------------------------
 * Known verification message (must match the message used when the
 * key_verification_msgs/*.msg files were signed).
 *
 * TODO: Decide on the canonical message content and update this constant
 *       together with the signature files. See open question in README.rst.
 * ---------------------------------------------------------------------------
 */
#define MFG_KEY_VERIFY_MESSAGE     "manufacturing_key_verification_v1"
#define MFG_KEY_VERIFY_MESSAGE_LEN (sizeof(MFG_KEY_VERIFY_MESSAGE) - 1U)

/* ---------------------------------------------------------------------------
 * Signature length for Ed25519 (64 bytes).
 * ---------------------------------------------------------------------------
 */
#define ED25519_SIGNATURE_LEN 64U

/* ---------------------------------------------------------------------------
 * Slot assignment for UROT public keys.
 *   Ed25519 keys occupy 2 consecutive KMU slots (255-bit key = 2 × 16-byte
 *   KMU slots), so gen0 occupies slots 120–121, gen1 occupies 124–125.
 * ---------------------------------------------------------------------------
 */
static const struct {
	const char *name;
	int         slot_id;
} urot_key_slots[] = {
	{ "urot_pubkey_gen0", CONFIG_MFG_UROT_KEY_GEN0_KMU_SLOT },
	{ "urot_pubkey_gen1", CONFIG_MFG_UROT_KEY_GEN1_KMU_SLOT },
};

/* ---------------------------------------------------------------------------
 * Check whether a KMU slot is already occupied.
 * Returns true if a key is present, false if the slot is empty (or the key
 * cannot be queried).
 * ---------------------------------------------------------------------------
 */
static bool slot_is_occupied(int slot_id)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_RAW, slot_id);

	mbedtls_svc_key_id_t svc_id = mbedtls_svc_key_id_make(0, key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(svc_id, &attr);

	psa_reset_key_attributes(&attr);
	return status == PSA_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * Check expected attributes for a KMU-stored key.
 * Logs mismatches between expected and actual attributes.
 * Returns true if attributes match, false otherwise.
 * ---------------------------------------------------------------------------
 */
static bool check_key_attributes(int slot_id, const char *key_name)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_RAW, slot_id);

	mbedtls_svc_key_id_t svc_id = mbedtls_svc_key_id_make(0, key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(svc_id, &attr);

	if (status != PSA_SUCCESS) {
		MFG_LOG_ERR("%s already provisioned, but cannot read attributes (status=%d).\n",
			    key_name, status);
		psa_reset_key_attributes(&attr);
		return false;
	}

	bool ok = true;
	psa_algorithm_t    actual_alg   = psa_get_key_algorithm(&attr);
	psa_key_usage_t    actual_usage = psa_get_key_usage_flags(&attr);
	psa_key_type_t     actual_type  = psa_get_key_type(&attr);

	psa_algorithm_t    expected_alg   = PSA_ALG_PURE_EDDSA;
	psa_key_usage_t    expected_usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE;
	psa_key_type_t     expected_type  =
		PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS);

	if (actual_alg != expected_alg || actual_usage != expected_usage ||
	    actual_type != expected_type) {
		MFG_LOG_ERR("%s already provisioned, but its attributes are incorrect\n", key_name);
		MFG_LOG_ERR("  Expected algorithm: PSA_ALG_PURE_EDDSA (0x%08x), as-is: 0x%08x\n",
			    expected_alg, actual_alg);
		MFG_LOG_ERR("  Expected usage: PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE"
			    " (0x%08x), as-is: 0x%08x\n",
			    expected_usage, actual_usage);
		MFG_LOG_ERR("  Expected type: ECC Ed25519 public key (0x%04x), as-is: 0x%04x\n",
			    expected_type, actual_type);
		ok = false;
	}

	psa_reset_key_attributes(&attr);
	return ok;
}

/* ---------------------------------------------------------------------------
 * Provision a single Ed25519 public key to a KMU slot.
 * ---------------------------------------------------------------------------
 */
static bool provision_key(const char *key_name, int slot_id,
			  const uint8_t *key_data, size_t key_len)
{
	MFG_LOG_INF("Provisioning %s to KMU, slot %d...", key_name, slot_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_RAW, slot_id);

	psa_set_key_id(&attr, mbedtls_svc_key_id_make(0, key_id));

	/*
	 * Lifetime: persistent in CRACEN KMU with rotating revocation policy.
	 *
	 * Revocation policy options:
	 *   PSA_KEY_PERSISTENCE_DEFAULT          — rotating (slot reusable after deletion)
	 *   CRACEN_KEY_PERSISTENCE_REVOKABLE     — once deleted, slot cannot be reprovisioned
	 *   CRACEN_KEY_PERSISTENCE_READ_ONLY     — erasable only by ERASEALL
	 *
	 * For UROT public keys used for secure boot, REVOKABLE is typical in
	 * production to prevent re-provisioning with a compromised key.
	 */
	psa_set_key_lifetime(&attr,
		PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
			PSA_KEY_PERSISTENCE_DEFAULT,
			PSA_KEY_LOCATION_CRACEN_KMU));

	psa_set_key_type(&attr,
		PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr,
		PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);

	mbedtls_svc_key_id_t imported_key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_status_t status = psa_import_key(&attr, key_data, key_len, &imported_key_id);

	psa_reset_key_attributes(&attr);

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF(" OK\n");
		return true;
	}

	MFG_LOG_INF(" FAIL\n");
	MFG_LOG_ERR("The cause is unknown. Possible reason — a key was provisioned\n");
	MFG_LOG_ERR("and revoked from given KMU slot.\n");
	return false;
}

/* ---------------------------------------------------------------------------
 * Verify a KMU-stored key by performing a signature check.
 *
 * The verification message is the fixed string MFG_KEY_VERIFY_MESSAGE.
 * The expected signature is read from the mfg_urot_keys table (msg file).
 *
 * The signature file must be a raw 64-byte Ed25519 signature of the
 * verification message, computed with the PRIVATE key counterpart.
 * ---------------------------------------------------------------------------
 */
static bool verify_key_signature(const char *key_name, int slot_id,
				 const uint8_t *sig, size_t sig_len)
{
	MFG_LOG_INF("Performing signature check using %s (KMU stored)...", key_name);

	if (sig == NULL || sig_len != ED25519_SIGNATURE_LEN) {
		MFG_LOG_INF(" SKIP (no verification message file found for %s)\n", key_name);
		MFG_LOG_ERR("Place a signed message file at "
			    "keys/key_verification_msgs/%s_signed.msg\n", key_name);
		return false;
	}

	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_RAW, slot_id);

	mbedtls_svc_key_id_t svc_id = mbedtls_svc_key_id_make(0, key_id);

	psa_status_t status = psa_verify_message(
		svc_id,
		PSA_ALG_PURE_EDDSA,
		(const uint8_t *)MFG_KEY_VERIFY_MESSAGE, MFG_KEY_VERIFY_MESSAGE_LEN,
		sig, sig_len);

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF(" OK\n");
		return true;
	}

	MFG_LOG_INF(" FAIL\n");
	MFG_LOG_ERR("Perhaps a verification message file was signed by a private key\n");
	MFG_LOG_ERR("from other key pair.\n");
	MFG_LOG_ERR("Generate a new key pair and/or sign again message verification file\n");
	MFG_LOG_ERR("and build this app again.\n");
	return false;
}

/* ---------------------------------------------------------------------------
 * Look up the verification message (signature) for a given key by name.
 * Returns NULL if not found.
 * ---------------------------------------------------------------------------
 */
static const uint8_t *find_sig_for_key(const char *key_name, size_t *sig_len_out)
{
	/*
	 * The pem_to_c.py script generates a C identifier for each .msg file
	 * by replacing non-alphanumeric characters with underscores.
	 * "urot_pubkey_gen0_signed" maps to the array "urot_pubkey_gen0_signed".
	 *
	 * We iterate over all known keys from provisioned_keys.h by name.
	 * For now, the two UROT keys have hardcoded names — extend this list
	 * as you add more keys.
	 */
#if defined(urot_pubkey_gen0_signed)
	if (strcmp(key_name, "urot_pubkey_gen0") == 0) {
		*sig_len_out = urot_pubkey_gen0_signed_len;
		return urot_pubkey_gen0_signed;
	}
#endif
#if defined(urot_pubkey_gen1_signed)
	if (strcmp(key_name, "urot_pubkey_gen1") == 0) {
		*sig_len_out = urot_pubkey_gen1_signed_len;
		return urot_pubkey_gen1_signed;
	}
#endif
	*sig_len_out = 0;
	return NULL;
}

/* ---------------------------------------------------------------------------
 * Step 4 entry point
 * ---------------------------------------------------------------------------
 */
void key_step4_provision_all(void)
{
	MFG_LOG_STEP("Validating secure boot and ADAC keys");
	MFG_LOG_INF("Location to place keys: 'keys' directory.\n");

	bool any_example_key = false;

	for (size_t i = 0; i < MFG_NUM_UROT_KEYS; i++) {
		const mfg_key_info_t *ki = &mfg_urot_keys[i];

		/* ----- Format check ----- */
		MFG_LOG_INF("Validating %s...", ki->filename);

		if (ki->len == 0) {
			MFG_LOG_INF(" FAIL (does not contain a public key — placeholder detected)\n");
			MFG_LOG_ERR("Generate your own keys and build this app again.\n");
			recovery_suspend(false);
		}

		if (ki->is_example) {
			MFG_LOG_INF(" OK (known public key from sample application)\n");
			any_example_key = true;
			continue;
		}

		MFG_LOG_INF(" OK\n");
	}

	if (any_example_key) {
		MFG_LOG_INF("\nKnown public keys shall not be utilized in end product.\n");
		MFG_LOG_INF("If you manufacture the end product — generate your own keys, "
			    "and build this app again.\n");
		MFG_LOG_INF("Continuing execution in 5 seconds.\n");
		k_sleep(K_SECONDS(5));
	}

	/* ----- Provision or verify each UROT key ----- */
	for (size_t i = 0; i < ARRAY_SIZE(urot_key_slots); i++) {
		const char *key_name = urot_key_slots[i].name;
		int         slot_id  = urot_key_slots[i].slot_id;

		/* Find matching key data from the generated header. */
		const mfg_key_info_t *ki = NULL;

		for (size_t j = 0; j < MFG_NUM_UROT_KEYS; j++) {
			/* Match by the C identifier embedded in the filename. */
			const char *fname = mfg_urot_keys[j].filename;
			/* Strip ".pem" suffix for comparison. */
			size_t fname_base_len = strlen(fname);

			if (fname_base_len > 4 &&
			    strncmp(fname, key_name, strlen(key_name)) == 0) {
				ki = &mfg_urot_keys[j];
				break;
			}
		}

		if (ki == NULL || ki->len == 0) {
			continue; /* placeholder keys skipped above */
		}

		if (slot_is_occupied(slot_id)) {
			MFG_LOG_INF("%s already provisioned.\n", key_name);

			if (!check_key_attributes(slot_id, key_name)) {
				recovery_suspend(false);
			}
		} else {
			if (!provision_key(key_name, slot_id, ki->data, ki->len)) {
				recovery_suspend(false);
			}
		}

		/* ----- Signature verification ----- */
		size_t sig_len = 0;
		const uint8_t *sig = find_sig_for_key(key_name, &sig_len);

		if (!verify_key_signature(key_name, slot_id, sig, sig_len)) {
			recovery_suspend(false);
		}
	}
}

/* ---------------------------------------------------------------------------
 * Step 12 — Revoke manufacturing application authentication key
 * ---------------------------------------------------------------------------
 */
void key_step12_revoke_mfg_key(void)
{
	MFG_LOG_INF("Revoking the MANUFACTURING_APP_KEY...");

	/*
	 * The manufacturing app key is stored in KMU slot
	 * CONFIG_MFG_APP_KEY_KMU_SLOT. Calling psa_destroy_key() on it
	 * revokes the slot according to the key's revocation policy:
	 *
	 *   CRACEN_KEY_PERSISTENCE_REVOKABLE  — slot transitions to 'Erased';
	 *                                       cannot be re-provisioned.
	 *   PSA_KEY_PERSISTENCE_DEFAULT       — slot transitions to 'Erased';
	 *                                       CAN be re-provisioned (ROTATING).
	 *
	 * The policy is set when the key is provisioned (typically by BL1/BL2).
	 * Verify with the bootloader configuration that the intended policy is used.
	 */
	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_RAW, CONFIG_MFG_APP_KEY_KMU_SLOT);

	mbedtls_svc_key_id_t svc_id = mbedtls_svc_key_id_make(0, key_id);

	psa_status_t status = psa_destroy_key(svc_id);

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF(" OK\n");
	} else {
		MFG_LOG_INF(" FAIL (psa_destroy_key returned %d)\n", status);
		MFG_LOG_ERR("MANUFACTURING_APP_KEY could not be revoked.\n");
		MFG_LOG_ERR("The key may not be provisioned in slot %d, or the slot is already\n",
			    CONFIG_MFG_APP_KEY_KMU_SLOT);
		MFG_LOG_ERR("empty. Continuing — the manufacturing process is still complete.\n");
	}

	MFG_LOG_INF("\nMANUFACTURING_APP_KEY was utilized to authenticate Manufacturing "
		    "(this) application.\n");
}
