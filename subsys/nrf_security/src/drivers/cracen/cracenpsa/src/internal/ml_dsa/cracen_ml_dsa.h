/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef CRACEN_INTERNAL_ML_DSA_H
#define CRACEN_INTERNAL_ML_DSA_H

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Verify a pure ML-DSA signature over a message.
 *
 *  Dispatches to mldsa-native's verify_internal for the parameter set
 *  encoded in the key attributes (key_bits == 128 / 192 / 256 selects
 *  ML-DSA-44 / -65 / -87 respectively). Only PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY
 *  is accepted; key pairs are intentionally rejected so the Oberon driver
 *  continues to own the sign path.
 *
 *  @param attributes        PSA key attributes.
 *  @param key_buffer        Raw bit-packed public key (rho || t1).
 *  @param key_buffer_size   Length of @p key_buffer in bytes.
 *  @param alg               PSA_ALG_ML_DSA or PSA_ALG_DETERMINISTIC_ML_DSA.
 *  @param input             Message bytes.
 *  @param input_length      Length of @p input in bytes.
 *  @param context           Optional FIPS 204 context string. May be NULL
 *                           when @p context_length is 0.
 *  @param context_length    Length of @p context. Must be < 256.
 *  @param signature         ML-DSA signature.
 *  @param signature_length  Length of @p signature in bytes.
 *
 *  @retval PSA_SUCCESS              Signature is valid.
 *  @retval PSA_ERROR_INVALID_SIGNATURE Signature is invalid.
 *  @retval PSA_ERROR_NOT_SUPPORTED  Algorithm / key type combination not
 *                                   handled by this driver (e.g. key pair,
 *                                   parameter set not configured).
 *  @retval PSA_ERROR_INVALID_ARGUMENT Sizes are inconsistent or context is
 *                                   too long.
 */
psa_status_t cracen_ml_dsa_verify_message(const psa_key_attributes_t *attributes,
					  const uint8_t *key_buffer, size_t key_buffer_size,
					  psa_algorithm_t alg, const uint8_t *input,
					  size_t input_length, const uint8_t *context,
					  size_t context_length, const uint8_t *signature,
					  size_t signature_length);

/** @brief Verify a HashML-DSA signature over a pre-hashed message.
 *
 *  Dispatches to mldsa-native's verify_pre_hash_internal. The PSA core
 *  passes the pre-computed digest as @p hash; the prehash algorithm is
 *  extracted from @p alg (the hash-algorithm half of PSA_ALG_HASH_ML_DSA).
 *  Same key/parameter-set conventions as cracen_ml_dsa_verify_message.
 */
psa_status_t cracen_ml_dsa_verify_hash(const psa_key_attributes_t *attributes,
				       const uint8_t *key_buffer, size_t key_buffer_size,
				       psa_algorithm_t alg, const uint8_t *hash,
				       size_t hash_length, const uint8_t *context,
				       size_t context_length, const uint8_t *signature,
				       size_t signature_length);

/** @brief Import a PSA ML-DSA public key into the CRACEN key buffer.
 *
 *  ML-DSA public keys are bit-packed byte strings (1312 / 1952 / 2592
 *  bytes for ML-DSA-44 / -65 / -87). The driver stores them verbatim in
 *  the key buffer.
 *
 *  Key pairs and the deterministic-derive key type are rejected with
 *  PSA_ERROR_NOT_SUPPORTED so the Oberon driver continues to own sign
 *  and keygen in v1.
 */
psa_status_t cracen_ml_dsa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
				      size_t data_length, uint8_t *key_buffer,
				      size_t key_buffer_size, size_t *key_buffer_length,
				      size_t *key_bits);

/** @brief Export a previously imported ML-DSA public key. */
psa_status_t cracen_ml_dsa_export_public_key(const psa_key_attributes_t *attributes,
					     const uint8_t *key_buffer, size_t key_buffer_size,
					     uint8_t *data, size_t data_size,
					     size_t *data_length);

#ifdef __cplusplus
}
#endif

#endif /* CRACEN_INTERNAL_ML_DSA_H */
