/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/ztest.h>
#include <pm_config.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "cracen_psa_kmu.h"
#include "psa_tests_common.h"

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_crypto_defs.h>
#else /* CONFIG_BUILD_WITH_TFM */
#include <hw_unique_key.h>
#endif /* CONFIG_BUILD_WITH_TFM */

/* ====================================================================== */
/*			Global variables/defines for the ikg key derivation test	  */

#define KEYSLOT HUK_KEYSLOT_MKEK
#define ENCRYPT_ALG PSA_ALG_GCM
#define IV_LEN 12
#define NRF_CRYPTO_TEST_AES_MAX_TEXT_SIZE (52)
#define NRF_CRYPTO_TEST_AES_ADDITIONAL_SIZE (36)
#define NRF_CRYPTO_TEST_AES_CCM_TAG_LENGTH (16)

static uint8_t m_plain_text[] = "Lorem ipsum dolor sit amet. This will be encrypted.";
static uint8_t m_encrypted_text[NRF_CRYPTO_TEST_AES_MAX_TEXT_SIZE +  +
				NRF_CRYPTO_TEST_AES_CCM_TAG_LENGTH];
static uint8_t m_decrypted_text[NRF_CRYPTO_TEST_AES_MAX_TEXT_SIZE];
static uint8_t m_additional_data[] = "This will be authenticated";
static uint32_t output_len;
static uint8_t iv[IV_LEN];
static psa_key_id_t key_id;
/* ====================================================================== */

LOG_MODULE_DECLARE(app, LOG_LEVEL_DBG);

psa_status_t derive_key(psa_key_attributes_t *attributes, uint8_t *key_label,
			uint32_t label_size, psa_key_id_t *key_id_out)
{
	uint8_t key_out[PSA_BITS_TO_BYTES(128)];
	psa_status_t status;
	int err;
	*key_id_out = PSA_KEY_ID_NULL;

	err = hw_unique_key_derive_key(KEYSLOT, NULL, 0,
					   key_label, label_size,
					   key_out, sizeof(key_out));
	if (err != HW_UNIQUE_KEY_SUCCESS) {
		LOG_DBG("hw_unique_key_derive_key returned error: %d", err);
		return PSA_ERROR_HARDWARE_FAILURE;
	}

	status = psa_import_key(attributes, key_out, sizeof(key_out), &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	*key_id_out = key_id;

	return PSA_SUCCESS;
}

int generate_key(void)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key_label[] = "IKG derivation sample label";
	psa_status_t status;

	/* Set the key attributes for the storage key */
	psa_set_key_usage_flags(&key_attributes,
			(PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT));
	psa_set_key_algorithm(&key_attributes, ENCRYPT_ALG);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);

	status = derive_key(&key_attributes, key_label, sizeof(key_label) - 1, &key_id);
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;

}

int encrypt_message(void)
{
	psa_status_t status;

	status = psa_generate_random(iv, IV_LEN);
	if (status != PSA_SUCCESS) {

		return APP_ERROR;
	}

	status = psa_aead_encrypt(key_id,
							ENCRYPT_ALG,
							iv,
							IV_LEN,
							m_additional_data,
							sizeof(m_additional_data),
							m_plain_text,
							sizeof(m_plain_text),
							m_encrypted_text,
							sizeof(m_encrypted_text),
							&output_len);
	if (status != PSA_SUCCESS) {
		LOG_DBG("psa_aead_encrypt returned error: %d", status);
		return APP_ERROR;
	}
	return APP_SUCCESS;
}

int decrypt_message(void)
{
	psa_status_t status;
	uint32_t output_len;

	status = psa_aead_decrypt(key_id,
							ENCRYPT_ALG,
							iv,
							IV_LEN,
							m_additional_data,
							sizeof(m_additional_data),
							m_encrypted_text,
							sizeof(m_encrypted_text),
							m_decrypted_text,
							sizeof(m_decrypted_text),
							&output_len);

	if (status != PSA_SUCCESS) {
		LOG_INF("Status is %d", status);
		return APP_ERROR;
	}
	return APP_SUCCESS;

}


int ikg_key_derivation_test(void)
{
	int status;

	status = crypto_init();
	TEST_VECTOR_ASSERT_EQUAL(0, status);

	status = generate_key();
	TEST_VECTOR_ASSERT_EQUAL(0, status);

	status = encrypt_message();
	TEST_VECTOR_ASSERT_EQUAL(0, status);

	status = decrypt_message();
	TEST_VECTOR_ASSERT_EQUAL(0, status);

	status = crypto_finish();
	TEST_VECTOR_ASSERT_EQUAL(0, status);

	if (status != APP_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

ZTEST(test_suite_ikg, ikg_key_derivation_test)
{
	ikg_key_derivation_test();
}
