/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * CRACEN PSA ML-DSA driver -- verify-only entry points and public-key
 * import/export. The lattice math runs in software via mldsa-native
 * (vendored from west); CRACEN's BA418 accelerates the FIPS-202 calls
 * underneath through the sx_xof_*-based shim in cracen_mldsa_fips202_shim.h.
 *
 * Sign / keygen / key-pair handling are intentionally returned as
 * PSA_ERROR_NOT_SUPPORTED in this version: the Oberon driver continues
 * to own those paths until a follow-up patch adds CRACEN sign support.
 */

#include "cracen_ml_dsa.h"
#include "cracen_mldsa_wrap.h"

#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psa/crypto_values.h>

#include <string.h>

/* Maximum context length per FIPS 204 (a single octet field). */
#define CRACEN_ML_DSA_MAX_CONTEXT_LEN 255

/* PSA key_bits encoding for ML-DSA parameter sets. */
#define CRACEN_ML_DSA_BITS_44 128
#define CRACEN_ML_DSA_BITS_65 192
#define CRACEN_ML_DSA_BITS_87 256

static int cracen_ml_dsa_psa_hash_to_prehash(psa_algorithm_t hash_alg)
{
	switch (hash_alg) {
	case PSA_ALG_SHA_224:
		return MLD_PREHASH_SHA2_224;
	case PSA_ALG_SHA_256:
		return MLD_PREHASH_SHA2_256;
	case PSA_ALG_SHA_384:
		return MLD_PREHASH_SHA2_384;
	case PSA_ALG_SHA_512:
		return MLD_PREHASH_SHA2_512;
	case PSA_ALG_SHA_512_224:
		return MLD_PREHASH_SHA2_512_224;
	case PSA_ALG_SHA_512_256:
		return MLD_PREHASH_SHA2_512_256;
	case PSA_ALG_SHA3_224:
		return MLD_PREHASH_SHA3_224;
	case PSA_ALG_SHA3_256:
		return MLD_PREHASH_SHA3_256;
	case PSA_ALG_SHA3_384:
		return MLD_PREHASH_SHA3_384;
	case PSA_ALG_SHA3_512:
		return MLD_PREHASH_SHA3_512;
	default:
		return -1;
	}
}

static psa_status_t cracen_ml_dsa_mld_err_to_psa(int mld_err)
{
	if (mld_err == 0) {
		return PSA_SUCCESS;
	}
	/* mldsa-native returns MLD_ERR_FAIL for both an invalid signature and
	 * for input validation failures inside verify_internal (sig length
	 * mismatch, hint-decoding rejection, c̃-mismatch, etc.). All of these
	 * surface to PSA as INVALID_SIGNATURE - the safe, conservative
	 * mapping for an external verify path. */
	return PSA_ERROR_INVALID_SIGNATURE;
}

static psa_status_t cracen_ml_dsa_check_common(const psa_key_attributes_t *attributes,
					       size_t context_length, size_t *out_bits)
{
	psa_key_type_t type = psa_get_key_type(attributes);

	if (!PSA_KEY_TYPE_IS_ML_DSA(type)) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (type != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
		/* Key pairs / DERIVE keys -> let the Oberon driver handle
		 * them. */
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (context_length > CRACEN_ML_DSA_MAX_CONTEXT_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	*out_bits = psa_get_key_bits(attributes);
	return PSA_SUCCESS;
}

/* Pure ML-DSA verify (no prehash). Dispatches by parameter set. */
static psa_status_t cracen_ml_dsa_pure_verify(size_t bits, const uint8_t *key_buffer,
					      size_t key_buffer_size, const uint8_t *input,
					      size_t input_length, const uint8_t *context,
					      size_t context_length, const uint8_t *signature,
					      size_t signature_length)
{
	int rc;

	switch (bits) {
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
	case CRACEN_ML_DSA_BITS_44:
		if (key_buffer_size != MLDSA44_PUBLICKEYBYTES ||
		    signature_length != MLDSA44_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa44_verify(signature, signature_length, input, input_length,
					   context, context_length, key_buffer);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
	case CRACEN_ML_DSA_BITS_65:
		if (key_buffer_size != MLDSA65_PUBLICKEYBYTES ||
		    signature_length != MLDSA65_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa65_verify(signature, signature_length, input, input_length,
					   context, context_length, key_buffer);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
	case CRACEN_ML_DSA_BITS_87:
		if (key_buffer_size != MLDSA87_PUBLICKEYBYTES ||
		    signature_length != MLDSA87_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa87_verify(signature, signature_length, input, input_length,
					   context, context_length, key_buffer);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
}

/* HashML-DSA verify (pre-hashed message). Dispatches by parameter set. */
static psa_status_t cracen_ml_dsa_prehash_verify(size_t bits, int prehash,
						 const uint8_t *key_buffer,
						 size_t key_buffer_size, const uint8_t *hash,
						 size_t hash_length, const uint8_t *context,
						 size_t context_length, const uint8_t *signature,
						 size_t signature_length)
{
	int rc;

	switch (bits) {
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
	case CRACEN_ML_DSA_BITS_44:
		if (key_buffer_size != MLDSA44_PUBLICKEYBYTES ||
		    signature_length != MLDSA44_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa44_verify_pre_hash_internal(signature, signature_length, hash,
							     hash_length, context, context_length,
							     key_buffer, prehash);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
	case CRACEN_ML_DSA_BITS_65:
		if (key_buffer_size != MLDSA65_PUBLICKEYBYTES ||
		    signature_length != MLDSA65_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa65_verify_pre_hash_internal(signature, signature_length, hash,
							     hash_length, context, context_length,
							     key_buffer, prehash);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
	case CRACEN_ML_DSA_BITS_87:
		if (key_buffer_size != MLDSA87_PUBLICKEYBYTES ||
		    signature_length != MLDSA87_BYTES) {
			return PSA_ERROR_INVALID_SIGNATURE;
		}
		rc = cracen_mldsa87_verify_pre_hash_internal(signature, signature_length, hash,
							     hash_length, context, context_length,
							     key_buffer, prehash);
		return cracen_ml_dsa_mld_err_to_psa(rc);
#endif
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
}

psa_status_t cracen_ml_dsa_verify_message(const psa_key_attributes_t *attributes,
					  const uint8_t *key_buffer, size_t key_buffer_size,
					  psa_algorithm_t alg, const uint8_t *input,
					  size_t input_length, const uint8_t *context,
					  size_t context_length, const uint8_t *signature,
					  size_t signature_length)
{
	psa_status_t status;
	size_t bits;

	if (!PSA_ALG_IS_ML_DSA(alg)) {
		/* HashML-DSA flows through verify_hash; this entry point
		 * only handles pure ML-DSA / DETERMINISTIC_ML_DSA. */
		return PSA_ERROR_NOT_SUPPORTED;
	}

	status = cracen_ml_dsa_check_common(attributes, context_length, &bits);
	if (status != PSA_SUCCESS) {
		return status;
	}

	return cracen_ml_dsa_pure_verify(bits, key_buffer, key_buffer_size, input, input_length,
					 context, context_length, signature, signature_length);
}

psa_status_t cracen_ml_dsa_verify_hash(const psa_key_attributes_t *attributes,
				       const uint8_t *key_buffer, size_t key_buffer_size,
				       psa_algorithm_t alg, const uint8_t *hash,
				       size_t hash_length, const uint8_t *context,
				       size_t context_length, const uint8_t *signature,
				       size_t signature_length)
{
	psa_status_t status;
	size_t bits;
	int prehash;

	if (!PSA_ALG_IS_HASH_ML_DSA(alg)) {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	prehash = cracen_ml_dsa_psa_hash_to_prehash(PSA_ALG_GET_HASH(alg));
	if (prehash < 0) {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	status = cracen_ml_dsa_check_common(attributes, context_length, &bits);
	if (status != PSA_SUCCESS) {
		return status;
	}

	return cracen_ml_dsa_prehash_verify(bits, prehash, key_buffer, key_buffer_size, hash,
					    hash_length, context, context_length, signature,
					    signature_length);
}

static size_t cracen_ml_dsa_pk_bytes_for(size_t bits)
{
	switch (bits) {
	case CRACEN_ML_DSA_BITS_44:
		return MLDSA44_PUBLICKEYBYTES;
	case CRACEN_ML_DSA_BITS_65:
		return MLDSA65_PUBLICKEYBYTES;
	case CRACEN_ML_DSA_BITS_87:
		return MLDSA87_PUBLICKEYBYTES;
	default:
		return 0;
	}
}

psa_status_t cracen_ml_dsa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
				      size_t data_length, uint8_t *key_buffer,
				      size_t key_buffer_size, size_t *key_buffer_length,
				      size_t *key_bits)
{
	psa_key_type_t type = psa_get_key_type(attributes);
	size_t expected;
	size_t bits;

	if (type != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	bits = psa_get_key_bits(attributes);
	if (bits == 0) {
		/* The PSA core lets drivers infer key_bits from the import
		 * payload when the application did not set it explicitly.
		 * Match data_length against each enabled parameter set. */
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_44)
		if (data_length == MLDSA44_PUBLICKEYBYTES) {
			bits = CRACEN_ML_DSA_BITS_44;
		} else
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_65)
		if (data_length == MLDSA65_PUBLICKEYBYTES) {
			bits = CRACEN_ML_DSA_BITS_65;
		} else
#endif
#if defined(CONFIG_PSA_NEED_CRACEN_ML_DSA_87)
		if (data_length == MLDSA87_PUBLICKEYBYTES) {
			bits = CRACEN_ML_DSA_BITS_87;
		} else
#endif
		{
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	expected = cracen_ml_dsa_pk_bytes_for(bits);
	if (expected == 0) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (data_length != expected) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (key_buffer_size < expected) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(key_buffer, data, expected);
	*key_buffer_length = expected;
	*key_bits = bits;

	return PSA_SUCCESS;
}

psa_status_t cracen_ml_dsa_export_public_key(const psa_key_attributes_t *attributes,
					     const uint8_t *key_buffer, size_t key_buffer_size,
					     uint8_t *data, size_t data_size,
					     size_t *data_length)
{
	psa_key_type_t type = psa_get_key_type(attributes);
	size_t expected;

	if (type != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	expected = cracen_ml_dsa_pk_bytes_for(psa_get_key_bits(attributes));
	if (expected == 0 || expected != key_buffer_size) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (data_size < expected) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(data, key_buffer, expected);
	*data_length = expected;
	return PSA_SUCCESS;
}
