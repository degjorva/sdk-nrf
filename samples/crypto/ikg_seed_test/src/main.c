/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <cracen_psa.h>
#include <cracen_psa_key_ids.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#include "init.h"

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(ikg_key_derivation, LOG_LEVEL_DBG);

/* ====================================================================== */
/*		    Global variables/defines for the IKG nRF54L PSA key derivation example    */

/* The key id for the persistent key. The macros PSA_KEY_ID_USER_MIN and
 * PSA_KEY_ID_USER_MAX define the range of freely available key ids.
 */
#define SAMPLE_PERS_KEY_ID				69
#define SAMPLE_KEY_TYPE					PSA_KEY_TYPE_AES
#define SAMPLE_ALG					PSA_ALG_CTR
#define NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE (100)

static psa_key_id_t key_id;

static uint8_t seed[48] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
			   0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			   0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
			   0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};

/* Below text is used as plaintext for encryption/decryption */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE] = {
	"Example string to demonstrate basic usage of a persistent key."};

static uint8_t m_encrypted_text[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(
	SAMPLE_KEY_TYPE, SAMPLE_ALG, NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE)];
static uint8_t m_decrypted_text[NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE];
/* ====================================================================== */

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(key_id);
	if (status != PSA_ERROR_DATA_INVALID) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

__attribute__((used)) int provision_seed(void)
{
	psa_status_t status;

	LOG_INF("Provisioning seed...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_key_id_t seed_key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(
		CRACEN_KMU_KEY_USAGE_SCHEME_SEED, 183);

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_id(&key_attributes, seed_key_id);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_NONE);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RAW_DATA);
	psa_set_key_bits(&key_attributes, 384);

	PRINT_HEX("key_attributes", (uint8_t * ) &key_attributes, sizeof(key_attributes));

	status = psa_import_key(&key_attributes, seed, sizeof(seed), &seed_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key for seed failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int derive_protected_kmu_key(void)
{
	psa_status_t status;
	psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

	LOG_INF("Deriving persistent AES key using PSA APIs with IKG MKEK on nRF54L...");

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	int key_usage_scheme = CRACEN_KMU_KEY_USAGE_SCHEME_PROTECTED;
	key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(key_usage_scheme, SAMPLE_PERS_KEY_ID);

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attributes, SAMPLE_ALG);
	psa_set_key_type(&key_attributes, SAMPLE_KEY_TYPE);
	psa_set_key_bits(&key_attributes, 128);

	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_id(&key_attributes, key_id);

	status = psa_key_derivation_setup(&operation, PSA_ALG_SP800_108_COUNTER_CMAC);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_key_derivation_setup failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Use the CRACEN builtin MKEK (Master Key Encryption Key) as the secret input */
	status = psa_key_derivation_input_key(&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
					      CRACEN_BUILTIN_MKEK_ID);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_key_derivation_input_key failed! (Error: %d)", status);
		psa_key_derivation_abort(&operation);
		return APP_ERROR;
	}

	uint8_t key_label[] = "AES_ENCRYPTION_KEY";
	status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_LABEL,
						key_label, sizeof(key_label) - 1); /* -1 to exclude null terminator */
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_key_derivation_input_bytes failed! (Error: %d)", status);
		psa_key_derivation_abort(&operation);
		return APP_ERROR;
	}

	status = psa_key_derivation_output_key(&key_attributes, &operation, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_key_derivation_output_key failed! (Error: %d)", status);
		psa_key_derivation_abort(&operation);
		return APP_ERROR;
	}


	/* Make sure the key is not in memory anymore, has the same affect as resetting the device */
	status = psa_purge_key(key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_purge_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	psa_reset_key_attributes(&key_attributes);

	LOG_INF("Persistent key derived successfully using PSA APIs with IKG MKEK on nRF54L!");

	uint8_t buf[16] = {0};
	size_t  out_len = 0;
	status = psa_export_key(key_id, buf, sizeof(buf), &out_len);
	if (status != PSA_ERROR_NOT_PERMITTED) {
		LOG_INF("psa_export_key succeeded for protected key! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int use_persistent_key(void)
{
	uint32_t olen;
	psa_status_t status;

	status = psa_cipher_encrypt(key_id, SAMPLE_ALG, m_plain_text, sizeof(m_plain_text),
				    m_encrypted_text, sizeof(m_encrypted_text), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_encrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Encryption successful!");
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("Encrypted text", m_encrypted_text, sizeof(m_encrypted_text));

	status = psa_cipher_decrypt(key_id, SAMPLE_ALG, m_encrypted_text, sizeof(m_encrypted_text),
				    m_decrypted_text, sizeof(m_decrypted_text), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_decrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	PRINT_HEX("Decrypted text", m_decrypted_text, sizeof(m_decrypted_text));

	/* Check the validity of the decryption */
	if (memcmp(m_decrypted_text, m_plain_text,
		   NRF_CRYPTO_EXAMPLE_PERSISTENT_KEY_MAX_TEXT_SIZE) != 0) {
		LOG_INF("Error: Decrypted text doesn't match the plaintext");
		return APP_ERROR;
	}

	LOG_INF("Decryption successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting IKG secure-only PSA key derivation example for nRF54L...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}


	status = provision_seed();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}


	status = derive_protected_kmu_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = use_persistent_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
