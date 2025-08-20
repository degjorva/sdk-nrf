/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Stub implementations for PSA ITS functions when using CRACEN/KMU
 * instead of software Internal Trusted Storage.
 */

#include <psa/internal_trusted_storage.h>

psa_status_t psa_its_set(psa_storage_uid_t uid,
			 size_t data_length,
			 const void *p_data,
			 psa_storage_create_flags_t create_flags)
{
	/* Return error since using CRACEN/KMU for key storage instead of ITS */
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_get(psa_storage_uid_t uid,
			 size_t data_offset,
			 size_t data_size,
			 void *p_data,
			 size_t *p_data_length)
{
	/* Return error since using CRACEN/KMU for key storage instead of ITS */
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid,
			      struct psa_storage_info_t *p_info)
{
	/* Return error since using CRACEN/KMU for key storage instead of ITS */
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
	/* Return error since using CRACEN/KMU for key storage instead of ITS */
	return PSA_ERROR_NOT_SUPPORTED;
}