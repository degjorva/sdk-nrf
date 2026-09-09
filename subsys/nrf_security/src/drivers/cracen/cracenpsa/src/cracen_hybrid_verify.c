/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <cracen_hybrid_verify.h>

#include <stdbool.h>
#include <psa/crypto.h>
#include <cracen/common.h>
#include <cracen/hardware.h>
#include <cracen/statuscodes.h>
#include <internal/ml_dsa/cracen_ml_dsa.h>
#include <silexpk/cmddefs/ecc.h>
#include <silexpk/core.h>
#include <silexpk/ec_curves.h>
#include <silexpk/iomem.h>
#include <sxsymcrypt/hashdefs.h>

#define ML_DSA_65_SECURITY_BITS 192
#define ML_DSA_87_SECURITY_BITS 256
#define SHA_384_DIGEST_SIZE	48

static enum cracen_hybrid_verify_status ml_dsa_status_to_hybrid(psa_status_t status)
{
	switch (status) {
	case PSA_SUCCESS:
		return CRACEN_HYBRID_VERIFY_VALID;
	case PSA_ERROR_INVALID_SIGNATURE:
		return CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE;
	case PSA_ERROR_INVALID_ARGUMENT:
		return CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
	default:
		return CRACEN_HYBRID_VERIFY_ERROR;
	}
}

static enum cracen_hybrid_verify_status ecdsa_status_to_hybrid(int status)
{
	switch (status) {
	case SX_OK:
		return CRACEN_HYBRID_VERIFY_VALID;
	case SX_ERR_INVALID_SIGNATURE:
	case SX_ERR_OUT_OF_RANGE:
	case SX_ERR_POINT_NOT_ON_CURVE:
		return CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE;
	default:
		return CRACEN_HYBRID_VERIFY_ERROR;
	}
}

static enum cracen_hybrid_verify_status combine_results(
	const struct cracen_hybrid_verify_result *result)
{
	if (result->ml_dsa == CRACEN_HYBRID_VERIFY_ERROR ||
	    result->ecdsa == CRACEN_HYBRID_VERIFY_ERROR) {
		return CRACEN_HYBRID_VERIFY_ERROR;
	}

	if (result->ml_dsa == CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT ||
	    result->ecdsa == CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT) {
		return CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
	}

	if (result->ml_dsa == CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE ||
	    result->ecdsa == CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE) {
		return CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE;
	}

	return CRACEN_HYBRID_VERIFY_VALID;
}

static bool get_ml_dsa_security_bits(size_t public_key_length, size_t signature_length,
				     size_t *security_bits)
{
#if defined(PSA_NEED_CRACEN_ML_DSA_65)
	if (public_key_length == CRACEN_HYBRID_ML_DSA_65_PUBLIC_KEY_SIZE &&
	    signature_length == CRACEN_HYBRID_ML_DSA_65_SIGNATURE_SIZE) {
		*security_bits = ML_DSA_65_SECURITY_BITS;
		return true;
	}
#endif

#if defined(PSA_NEED_CRACEN_ML_DSA_87)
	if (public_key_length == CRACEN_HYBRID_ML_DSA_87_PUBLIC_KEY_SIZE &&
	    signature_length == CRACEN_HYBRID_ML_DSA_87_SIGNATURE_SIZE) {
		*security_bits = ML_DSA_87_SECURITY_BITS;
		return true;
	}
#endif

	return false;
}

static psa_status_t verify_ml_dsa(const uint8_t *message, size_t message_length,
				  const uint8_t *public_key, size_t public_key_length,
				  const uint8_t *signature, size_t signature_length,
				  size_t security_bits)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
	psa_set_key_bits(&attributes, security_bits);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA);

	return cracen_ml_dsa_verify(true, &attributes, public_key, public_key_length,
				    PSA_ALG_ML_DSA, message, message_length, NULL, 0,
				    signature, signature_length);
}

static int start_ecdsa(const uint8_t *public_key, const uint8_t *digest,
		       const uint8_t *signature, sx_pk_req *request)
{
	struct sx_pk_inops_ecdsa_verify inputs;
	int status;

	sx_pk_acquire_hw(request);
	sx_pk_set_cmd(request, SX_PK_CMD_ECDSA_VER);
	status = sx_pk_list_ecc_inslots(request, &sx_curve_nistp384, 0,
				       (struct sx_pk_slot *)&inputs);
	if (status != SX_OK) {
		/*
		 * sx_pk_list_ecc_inslots() currently releases the request on
		 * every error path. Do not release it a second time here.
		 */
		return status;
	}

	sx_wrpkmem(inputs.qx.addr, public_key, SHA_384_DIGEST_SIZE);
	sx_wrpkmem(inputs.qy.addr, public_key + SHA_384_DIGEST_SIZE,
		   SHA_384_DIGEST_SIZE);
	sx_wrpkmem(inputs.r.addr, signature, SHA_384_DIGEST_SIZE);
	sx_wrpkmem(inputs.s.addr, signature + SHA_384_DIGEST_SIZE,
		   SHA_384_DIGEST_SIZE);
	sx_wrpkmem(inputs.h.addr, digest, SHA_384_DIGEST_SIZE);
	sx_pk_run(request);

	return SX_OK;
}

enum cracen_hybrid_verify_status cracen_hybrid_verify(
	const uint8_t *message, size_t message_length,
	const uint8_t *ml_dsa_public_key, size_t ml_dsa_public_key_length,
	const uint8_t *ml_dsa_signature, size_t ml_dsa_signature_length,
	const uint8_t *ecdsa_public_key, size_t ecdsa_public_key_length,
	const uint8_t *ecdsa_signature, size_t ecdsa_signature_length,
	struct cracen_hybrid_verify_result *result)
{
	uint8_t digest[SHA_384_DIGEST_SIZE];
	sx_pk_req request;
	psa_status_t ml_dsa_status;
	int ecdsa_status;
	bool ecdsa_started = false;
	bool message_is_valid;
	bool ml_dsa_input_is_valid;
	bool ecdsa_input_is_valid;
	size_t ml_dsa_security_bits = 0;

	if (result == NULL) {
		return CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
	}

	result->combined = CRACEN_HYBRID_VERIFY_ERROR;
	result->ml_dsa = CRACEN_HYBRID_VERIFY_ERROR;
	result->ecdsa = CRACEN_HYBRID_VERIFY_ERROR;

	message_is_valid = message != NULL || message_length == 0;
	ml_dsa_input_is_valid =
		ml_dsa_public_key != NULL &&
		ml_dsa_signature != NULL &&
		get_ml_dsa_security_bits(ml_dsa_public_key_length, ml_dsa_signature_length,
					 &ml_dsa_security_bits);
	ecdsa_input_is_valid =
		ecdsa_public_key != NULL &&
		ecdsa_public_key_length == CRACEN_HYBRID_ECDSA_PUBLIC_KEY_SIZE &&
		ecdsa_signature != NULL &&
		ecdsa_signature_length == CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE;

	if (!message_is_valid) {
		result->ml_dsa = CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
		result->ecdsa = CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
		goto exit;
	}

	if (!ml_dsa_input_is_valid) {
		result->ml_dsa = CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
	}
	if (!ecdsa_input_is_valid) {
		result->ecdsa = CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT;
	}
	if (!ml_dsa_input_is_valid && !ecdsa_input_is_valid) {
		goto exit;
	}

	if (cracen_init() != PSA_SUCCESS) {
		goto exit;
	}

	if (ecdsa_input_is_valid) {
		ecdsa_status = cracen_hash_input(message, message_length,
						 &sxhashalg_sha2_384, digest);
		if (ecdsa_status == SX_OK) {
			ecdsa_status = start_ecdsa(ecdsa_public_key, digest,
						  ecdsa_signature, &request);
			ecdsa_started = ecdsa_status == SX_OK;
		}

		if (!ecdsa_started) {
			result->ecdsa = ecdsa_status_to_hybrid(ecdsa_status);
		}
	}

	if (ml_dsa_input_is_valid) {
		ml_dsa_status = verify_ml_dsa(message, message_length,
					      ml_dsa_public_key, ml_dsa_public_key_length,
					      ml_dsa_signature, ml_dsa_signature_length,
					      ml_dsa_security_bits);
		result->ml_dsa = ml_dsa_status_to_hybrid(ml_dsa_status);
	}

	if (ecdsa_started) {
		ecdsa_status = sx_pk_wait(&request);
		sx_pk_release_req(&request);
		result->ecdsa = ecdsa_status_to_hybrid(ecdsa_status);
	}

exit:
	result->combined = combine_results(result);
	return result->combined;
}
