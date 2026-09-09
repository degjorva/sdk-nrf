/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file
 * @brief Hybrid ML-DSA-65/87 and ECDSA P-384 verification.
 */

#ifndef CRACEN_HYBRID_VERIFY_H
#define CRACEN_HYBRID_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#if defined(CONFIG_PSA_NEED_CRACEN_HYBRID_VERIFY)

#define CRACEN_HYBRID_ML_DSA_65_PUBLIC_KEY_SIZE 1952
#define CRACEN_HYBRID_ML_DSA_65_SIGNATURE_SIZE  3309
#define CRACEN_HYBRID_ML_DSA_87_PUBLIC_KEY_SIZE 2592
#define CRACEN_HYBRID_ML_DSA_87_SIGNATURE_SIZE  4627
#define CRACEN_HYBRID_ECDSA_PUBLIC_KEY_SIZE      96
#define CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE       96

/**
 * @brief Result of a hybrid or component verification.
 */
enum cracen_hybrid_verify_status {
	CRACEN_HYBRID_VERIFY_VALID,
	CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
	CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
	CRACEN_HYBRID_VERIFY_ERROR,
};

/**
 * @brief Combined and component results from hybrid verification.
 */
struct cracen_hybrid_verify_result {
	enum cracen_hybrid_verify_status combined;
	enum cracen_hybrid_verify_status ml_dsa;
	enum cracen_hybrid_verify_status ecdsa;
};

/**
 * @brief Verify pure ML-DSA-65 or ML-DSA-87 and ECDSA P-384/SHA-384 signatures.
 *
 * Both signatures cover the same message. The ML-DSA public key and signature
 * use matching FIPS 204 encodings; their lengths select the ML-DSA parameter
 * set. The ECDSA public key is encoded as Qx || Qy and the signature as r || s,
 * with each component occupying 48 big-endian bytes.
 *
 * ECDSA verification is started before ML-DSA verification and completed
 * afterward, allowing PKE execution to overlap ML-DSA CPU and CryptoMaster
 * work.
 *
 * @warning The caller must serialize this function against all other Cracen
 * crypto operations. This fixed-profile prototype acquires PKE before
 * CryptoMaster; concurrent use with an operation that acquires those engines
 * in the opposite order can deadlock.
 *
 * @param[in] message Message covered by both signatures.
 * @param[in] message_length Message length in bytes.
 * @param[in] ml_dsa_public_key Encoded ML-DSA-65 or ML-DSA-87 public key.
 * @param[in] ml_dsa_public_key_length ML-DSA public-key length in bytes.
 * @param[in] ml_dsa_signature Encoded ML-DSA-65 or ML-DSA-87 signature.
 * @param[in] ml_dsa_signature_length ML-DSA signature length in bytes.
 * @param[in] ecdsa_public_key Encoded ECDSA P-384 public key.
 * @param[in] ecdsa_public_key_length ECDSA public-key length in bytes.
 * @param[in] ecdsa_signature Encoded ECDSA P-384 signature.
 * @param[in] ecdsa_signature_length ECDSA signature length in bytes.
 * @param[out] result Combined and per-signature verification results.
 *
 * @return The combined verification result.
 */
enum cracen_hybrid_verify_status cracen_hybrid_verify(
	const uint8_t *message, size_t message_length,
	const uint8_t *ml_dsa_public_key, size_t ml_dsa_public_key_length,
	const uint8_t *ml_dsa_signature, size_t ml_dsa_signature_length,
	const uint8_t *ecdsa_public_key, size_t ecdsa_public_key_length,
	const uint8_t *ecdsa_signature, size_t ecdsa_signature_length,
	struct cracen_hybrid_verify_result *result);

#endif /* CONFIG_PSA_NEED_CRACEN_HYBRID_VERIFY */

#endif /* CRACEN_HYBRID_VERIFY_H */
