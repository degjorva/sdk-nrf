/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _APP_JWT_H
#define _APP_JWT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file app_jwt.h
 *
 * @brief Generate a JWT with from application core.
 * @defgroup app_jwt JWT generation
 * @{
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <strings.h>

/** @brief Maximum size of a JWT string, could be used to allocate JWT
 *         output buffer.
 */
#define APP_JWT_STR_MAX_LEN 900

/** @brief Maximum valid duration for JWTs generated by user application */
#define APP_JWT_VALID_TIME_S_MAX (7 * 24 * 60 * 60)

/** @brief Default valid duration for JWTs generated by user application */
#define APP_JWT_VALID_TIME_S_DEF (10 * 60)

/** @brief UUID size in bytes */
#define APP_JWT_UUID_BYTE_SZ 16

/** @brief UUID v4 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx + '\0' */
#define APP_JWT_UUID_V4_STR_LEN (((APP_JWT_UUID_BYTE_SZ * 2) + 4) + 1)

/** @brief Size in bytes of each JWT String field */
#define APP_JWT_CLAIM_MAX_SIZE 64

/** @brief The type of key to be used for signing the JWT. */
enum app_jwt_key_type {
	JWT_KEY_TYPE_CLIENT_PRIV = 2,
	JWT_KEY_TYPE_ENDORSEMENT = 8,
};

/** @brief JWT signing algorithm */
enum app_jwt_alg_type {
	JWT_ALG_TYPE_ES256 = 0,
};

/** @brief JWT parameters required for JWT generation and pointer to generated JWT */
struct app_jwt_data {
	/** Sec tag to use for JWT signing */
	unsigned int sec_tag;
	/** Key type in the specified sec tag */
	enum app_jwt_key_type key_type;
	/** JWT signing algorithm */
	enum app_jwt_alg_type alg;

	/**
	 * Indicates if a 'kid' claim is required or not, if set to 1, 'kid' claim
	 * will contain sha256 of the signing key.
	 */
	bool add_keyid_to_header;

	/**
	 * NULL terminated 'jti' claim; Unique identifier; can be used to prevent the
	 * JWT from being replayed
	 */
	const char *json_token_id;
	/** NULL terminated 'sub' claim; the principal that is the subject of the JWT */
	const char *subject;
	/** NULL terminated 'aud' claim; intended recipient of the JWT */
	const char *audience;
	/** NULL terminated 'iss' claim; Issuer of the JWT */
	const char *issuer;

	/**
	 * Indicates if an issue timestamp is required or not, if set to 1, 'exp' claim
	 * will be present.
	 */
	bool add_timestamp;

	/**
	 * Corresponds to 'exp' claim; Defines how long the JWT will be valid.
	 * If application has a valid time source, and the 'iat' claim is present,
	 * the timestamp in seconds will be added to this value.
	 */
	uint32_t validity_s;

	/**
	 * Buffer to which the NULL terminated JWT will be copied.
	 * It is the responsibility of the user to provide a valid buffer.
	 * The returned JWT could be as long as 900 bytes, use the
	 * defined size value APP_JWT_STR_MAX_LEN to create your supplied return buffer.
	 */
	char *jwt_buf;
	/** Size of the user provided buffer. */
	size_t jwt_sz;
};

/**
 * @brief Generate a JWT using the supplied parameters. If successful,
 * the JWT string will be stored in the supplied struct.
 * You are responsible for providing a valid pointer to store the JWT.
 *
 * Subject, audience, token ID and issuer fields may be NULL in which case those
 * fields are left out from generated JWT token.
 *
 * All fields will be truncated to 64 characters, you should always provide null
 * terminated strings.
 *
 * The API does not verify the time source validity, it is up to the caller to make sure
 * that the system has access to a valid time source, otherwise "iat" field will
 * contain an arbitrary timestamp.
 *
 * @param[in,out] jwt Pointer to struct containing JWT parameters and result.
 *
 * @retval 0 If the operation was successful.
 * @retval -errno Negative errno for other failures.
 */
int app_jwt_generate(struct app_jwt_data *const jwt);

/**
 * @brief Get the device UUID from the secure domain
 * and return it as a NULL terminated string in the supplied buffer.
 * The device UUID can be used as a device identifier for cloud services and
 * for secure device management using the nRF Cloud Identity Service.
 *
 * UUID v4 defined by ITU-T X.667 | ISO/IEC 9834-8 has a length of 35 bytes, add
 * 1 byte for the atring termination character. You are expected to provide a buffer
 * of at least 36 bytes.
 *
 * @param[out] uuid_buffer Pointer to buffer where the device UUID string will be written to.
 * @param[in] uuid_buffer_size Size of the provided buffer.
 *
 * @retval 0 If the operation was successful.
 * @retval -errno Negative errno for other failures.
 */
int app_jwt_get_uuid(char *uuid_buffer, const size_t uuid_buffer_size);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _APP_JWT_H */
