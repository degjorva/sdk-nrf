/* ECC key pair generation.
 * Based on FIPS 186-4, section B.4.2 "Key Pair Generation by Testing
 * Candidates".
 *
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <silexpk/core.h>
#include <silexpk/iomem.h>
#include <silexpk/cmddefs/ecc.h>
#include <cracen/statuscodes.h>
#include "cracen_psa.h"
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>

#define MAX_ECC_ATTEMPTS 10
LOG_MODULE_REGISTER(ecc, LOG_LEVEL_DBG);

int ecc_create_genpubkey(const char *priv_key, char *pub_key, const struct sx_pk_ecurve *curve)
{
	const char **outputs;
	struct sx_pk_acq_req pkreq;
	struct sx_pk_inops_ecp_mult inputs;
	int opsz;
	int status;

	for (int i = 0; i <= MAX_ECC_ATTEMPTS; i++) {
		LOG_INF("ECC test");
		pkreq = sx_pk_acquire_req(SX_PK_CMD_ECC_PTMUL);
		if (pkreq.status) {
			return pkreq.status;
		}
		LOG_INF("list_ecc_inslots");
		pkreq.status =
			sx_pk_list_ecc_inslots(pkreq.req, curve, 0, (struct sx_pk_slot *)&inputs);
		if (pkreq.status) {
			return pkreq.status;
		}

		opsz = sx_pk_curve_opsize(curve);
		LOG_INF("curve_opsize");

		/* Write the private key (random) into ba414ep device memory */
		sx_wrpkmem(inputs.k.addr, priv_key, opsz);
		sx_pk_write_curve_gen(pkreq.req, curve, inputs.px, inputs.py);
		LOG_INF("curve_write");

		sx_pk_run(pkreq.req);
		LOG_INF("pk_has_finished");

		status = sx_pk_has_finished(pkreq.req);
		LOG_INF("sx_pk_wait");

		status = sx_pk_wait(pkreq.req);
		if (status != SX_OK) {
			return status;
		}
		LOG_INF("output_ops");
		/*  static int on_generated_public(struct sitask *t, struct siwq *wq) */
		outputs = sx_pk_get_output_ops(pkreq.req);
		LOG_INF("outputs");

		/* When countermeasures are used, the operation may fail with error code
		 * SX_ERR_NOT_INVERTIBLE. In this case we can try again.
		 */
		if (status == SX_ERR_NOT_INVERTIBLE) {
			sx_pk_release_req(pkreq.req);
			if (i == MAX_ECC_ATTEMPTS) {
				return SX_ERR_TOO_MANY_ATTEMPTS;
			}
		} else {
			break;
		}
	}
	sx_rdpkmem(pub_key, outputs[0], opsz);

	sx_rdpkmem(pub_key + opsz, outputs[1], opsz);
	sx_pk_release_req(pkreq.req);
	LOG_INF("last wait");
	return status;
}

int ecc_create_genprivkey(const struct sx_pk_ecurve *curve, char *priv_key, size_t priv_key_size)
{
	size_t keysz = (size_t)sx_pk_curve_opsize(curve);
	int status;
	int opsz = sx_pk_curve_opsize(curve);
	const char *curve_n = sx_pk_curve_order(curve);

	if (priv_key_size < keysz) {
		return SX_ERR_OUTPUT_BUFFER_TOO_SMALL;
	}

	/* generate private key, a random in [1, n-1], where n is the curve
	 * order
	 */
	status = rndinrange_create((const unsigned char *)curve_n, opsz, priv_key);

	return status;
}
