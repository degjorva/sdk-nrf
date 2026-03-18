/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Steps 7 and 8 — KeyRAM random and IKG seed provisioning.
 *
 * These operations are performed after the LCS transition to PROT Provisioning
 * (Step 6) because provisioning the IKG seed and MKEK in 'Manufacturing and
 * Test' would be caught by Step 2 on the next reboot as a security error.
 *
 * From a TF-M non-secure application:
 *
 * KeyRAM random (slots 248, 249):
 *   cracen_provision_prot_ram_inv_slots() is a Secure-side driver function.
 *   From NS, generate the random data and import it via psa_import_key() with
 *   CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED and the respective slot IDs.
 *
 *   Alternatively, if TF-M exposes this as a platform service, call it via
 *   the IPC interface.
 *
 *   For simplicity in this reference, the provisioning is implemented as a
 *   PSA key generation operation targeting the KMU slots directly.
 *
 * IKG seed (hw_unique_key):
 *   hw_unique_key_write_random() is a Secure-side library function that
 *   writes a random 48-byte seed to the CRACEN IKG seed KMU slots.
 *   From NS, this must go through a TF-M platform service.
 *
 *   TODO: Expose hw_unique_key_write_random() as a TF-M platform IPC call.
 *   Until then, the step is implemented as a stub.
 *
 * Slot revocation note:
 *   A KMU slot that held a REVOKABLE key and was subsequently revoked will
 *   appear empty to psa_get_key_attributes() but psa_import_key() / the
 *   underlying cracen_kmu_provision() will fail. The "unknown cause / possible
 *   reason" log message is the best achievable diagnostic in this case.
 */

#include "huk_provisioning.h"
#include "mfg_log.h"
#include "recovery.h"

#include <zephyr/kernel.h>
#include <psa/crypto.h>
#include <cracen_psa_kmu.h>
#include <cracen_psa_key_ids.h>

/* ---------------------------------------------------------------------------
 * Check whether a KMU slot is occupied via PSA attribute query.
 * ---------------------------------------------------------------------------
 */
static bool kmu_slot_is_occupied(int slot_id, enum cracen_kmu_metadata_key_usage_scheme scheme)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(scheme, slot_id);
	mbedtls_svc_key_id_t svc_id = mbedtls_svc_key_id_make(0, key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(svc_id, &attr);

	psa_reset_key_attributes(&attr);
	return status == PSA_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * Step 7 — Provision KeyRAM random data (protected RAM invalidation slots)
 * ---------------------------------------------------------------------------
 */
void huk_step7_provision_keyram_random(void)
{
	MFG_LOG_STEP("Provisioning of KeyRam Random");

	/*
	 * Check both slots. Since they are always provisioned together, checking
	 * slot 248 is sufficient; checking both is more defensive.
	 */
	bool slot1_ok = kmu_slot_is_occupied(PROTECTED_RAM_INVALIDATION_DATA_SLOT1,
					     CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED);
	bool slot2_ok = kmu_slot_is_occupied(PROTECTED_RAM_INVALIDATION_DATA_SLOT2,
					     CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED);

	if (slot1_ok && slot2_ok) {
		MFG_LOG_INF("KeyRam Random already provisioned.\n");
		return;
	}

	/*
	 * TODO: Call a TF-M platform service that wraps
	 * cracen_provision_prot_ram_inv_slots() on the Secure side.
	 *
	 * Pseudocode for the platform service:
	 *
	 *   psa_status_t cracen_provision_prot_ram_inv_slots();
	 *   // (Secure-side: generates random data and calls cracen_kmu_provision()
	 *   //  for slots 248 and 249 with CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED.)
	 *
	 * Alternative (direct PSA from NS — if TF-M proxy supports it):
	 *
	 *   uint8_t random_data[16];
	 *   for each slot (248, 249):
	 *     psa_generate_random(random_data, sizeof(random_data));
	 *     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	 *     psa_set_key_id(&attr, mbedtls_svc_key_id_make(0,
	 *         PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
	 *             CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED, slot)));
	 *     psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
	 *         PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	 *     psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	 *     psa_set_key_bits(&attr, 128);
	 *     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	 *     psa_set_key_algorithm(&attr, PSA_ALG_GCM);
	 *     mbedtls_svc_key_id_t out_id = MBEDTLS_SVC_KEY_ID_INIT;
	 *     psa_import_key(&attr, random_data, sizeof(random_data), &out_id);
	 */

	MFG_LOG_INF("Provisioning KeyRam Random to KMU, slot %d...",
		    PROTECTED_RAM_INVALIDATION_DATA_SLOT1);
	MFG_LOG_INF(" STUB (platform service not yet implemented)\n");
	MFG_LOG_INF("[STUB] In production, replace this stub with a TF-M platform service call.\n");

	/* Un-comment the block below after implementing the platform service:
	 *
	 * psa_status_t status = platform_svc_provision_prot_ram_inv_slots();
	 * if (status != PSA_SUCCESS) {
	 *     MFG_LOG_INF(" FAIL\n");
	 *     MFG_LOG_ERR("The cause is unknown. Possible reason — a key was provisioned\n");
	 *     MFG_LOG_ERR("and revoked from given KMU slot.\n");
	 *     recovery_suspend(true);
	 * }
	 * MFG_LOG_INF(" OK\n");
	 */
}

/* ---------------------------------------------------------------------------
 * Step 8 — Provision IKG seed and log derived key information
 * ---------------------------------------------------------------------------
 */
void huk_step8_provision_ikg_seed(void)
{
	MFG_LOG_STEP("Provisioning of IKG seed");

	/*
	 * Check IKG seed presence by attempting to export the IAK public key.
	 * psa_export_public_key() will succeed only if the IKG seed is present.
	 */
	uint8_t iak_pub[32];
	size_t  iak_pub_len = 0;

	mbedtls_svc_key_id_t iak_id =
		mbedtls_svc_key_id_make(0, CRACEN_BUILTIN_IDENTITY_KEY_ID);

	psa_status_t status = psa_export_public_key(iak_id,
						    iak_pub, sizeof(iak_pub),
						    &iak_pub_len);

	if (status == PSA_SUCCESS) {
		MFG_LOG_INF("IKG seed already provisioned.\n");
		/* Fall through to log derived key information. */
	} else {
		/*
		 * TODO: Call a TF-M platform service that wraps
		 * hw_unique_key_write_random() on the Secure side.
		 *
		 * hw_unique_key_write_random() generates a cryptographically
		 * random 48-byte (384-bit) value and writes it to the KMU
		 * IKG seed slots using CRACEN_KMU_KEY_USAGE_SCHEME_SEED.
		 * The CRACEN IKG then uses this seed to derive all device keys.
		 *
		 * Pseudocode:
		 *   int err = platform_svc_hw_unique_key_write_random();
		 *   if (err != HW_UNIQUE_KEY_SUCCESS) {
		 *       MFG_LOG_INF(" FAIL\n");
		 *       MFG_LOG_ERR("The cause is unknown. Possible reason — a key was "
		 *                   "provisioned and revoked from given KMU slot.\n");
		 *       recovery_suspend(true);
		 *   }
		 *   MFG_LOG_INF(" OK\n");
		 *
		 * After writing the seed, re-export the IAK public key:
		 *   status = psa_export_public_key(iak_id, iak_pub, sizeof(iak_pub), &iak_pub_len);
		 */

		MFG_LOG_INF("Provisioning IKG seed to KMU, slot %d...",
			    CONFIG_CRACEN_IKG_SEED_KMU_SLOT);
		MFG_LOG_INF(" STUB (platform service not yet implemented)\n");
		MFG_LOG_INF("[STUB] In production, replace this stub with a TF-M platform service.\n");
		return;
	}

	/* ----- Log derived key information ----- */
	MFG_LOG_INF("\nInitial Attestation Key (IAK, also known as Identity Key) "
		    "ID: 0x%08X\n", CRACEN_BUILTIN_IDENTITY_KEY_ID);
	MFG_LOG_INF("Public key: ");
	for (size_t i = 0; i < iak_pub_len; i++) {
		MFG_LOG_INF("%02x", iak_pub[i]);
		if (i == 3) {
			MFG_LOG_INF(" ... ");
		}
	}
	MFG_LOG_INF("\n\n");

	MFG_LOG_INF("Master Key Encryption Key (MKEK) ID: 0x%08X\n", CRACEN_BUILTIN_MKEK_ID);
	MFG_LOG_INF("Master External Key (MEXT) ID:       0x%08X\n", CRACEN_BUILTIN_MEXT_ID);

	/*
	 * PSA Instance ID is derived from the IAK public key.
	 * Format TBD — typically a hash of the public key.
	 *
	 * TODO: Compute PSA Instance ID per the PSA attestation specification:
	 *   uint8_t instance_id[33]; // 0x01 || SHA-256(pub_key)
	 *   instance_id[0] = 0x01;   // GUID type byte
	 *   psa_hash_compute(PSA_ALG_SHA_256, iak_pub, iak_pub_len,
	 *                    instance_id + 1, 32, &hash_len);
	 */
	MFG_LOG_INF("PSA Instance ID: <TBD — computed from IAK public key>\n");
}
