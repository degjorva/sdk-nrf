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
#include "../include/sicrypto/sicrypto.h"
#include "../include/sicrypto/ecc.h"
#include <cracen/statuscodes.h>
#include "rndinrange.h"
#include "waitqueue.h"
#include "final.h"
#include "util.h"

#define MAX_ECC_ATTEMPTS 10

static void run_ecc_generate_public_key(struct sitask *t);

static int on_generated_public(struct sitask *t, struct siwq *wq)
{
	(void)wq;
	const char **outputs = sx_pk_get_output_ops(t->pk);
	const int opsz = sx_pk_curve_opsize(t->params.ecc.sk->curve);

	/* When countermeasures are used, the operation may fail with error code
	 * SX_ERR_NOT_INVERTIBLE. In this case we can try again.
	 */
	if (t->statuscode == SX_ERR_NOT_INVERTIBLE) {
		if (t->params.ecc.attempts--) {
			sx_pk_release_req(t->pk);
			t->statuscode = SX_ERR_HW_PROCESSING;
			run_ecc_generate_public_key(t);
		} else {
			return si_task_mark_final(t, SX_ERR_TOO_MANY_ATTEMPTS);
		}
	}

	sx_rdpkmem(t->params.ecc.pk->qx, outputs[0], opsz);
	sx_rdpkmem(t->params.ecc.pk->qy, outputs[1], opsz);
	sx_pk_release_req(t->pk);

	return t->statuscode;
}

static void run_ecc_generate_public_key(struct sitask *t)
{
	struct sx_pk_acq_req pkreq;
	struct sx_pk_inops_ecp_mult inputs;
	int opsz;

	pkreq = sx_pk_acquire_req(SX_PK_CMD_ECC_PTMUL);
	if (pkreq.status) {
		si_task_mark_final(t, pkreq.status);
		return;
	}

	pkreq.status = sx_pk_list_ecc_inslots(pkreq.req, t->params.ecc.sk->curve, 0,
					      (struct sx_pk_slot *)&inputs);
	if (pkreq.status) {
		si_task_mark_final(t, pkreq.status);
		return;
	}
	t->pk = pkreq.req;
	opsz = sx_pk_curve_opsize(t->params.ecc.sk->curve);

	/* Write the private key (random) into ba414ep device memory */
	sx_wrpkmem(inputs.k.addr, t->params.ecc.sk->d, opsz);
	sx_pk_write_curve_gen(pkreq.req, t->params.ecc.sk->curve, inputs.px, inputs.py);

	sx_pk_run(pkreq.req);

	t->actions.status = si_silexpk_status;
	t->actions.wait = si_silexpk_wait;

	si_wq_run_after(t, &t->params.ecc.wq, on_generated_public);
}

static int on_generated_private_rnd(struct sitask *t, struct siwq *wq)
{
	int opsz = sx_pk_curve_opsize(t->params.ecc.sk->curve);

	(void)wq;

	if (t->statuscode != SX_OK) {
		return t->statuscode;
	}

	memcpy(t->params.ecc.sk->d, t->workmem, opsz);

	return SX_OK;
}

static void run_ecc_generate_private_rnd(struct sitask *t)
{
	int opsz = sx_pk_curve_opsize(t->params.ecc.sk->curve);
	const char *curve_n = sx_pk_curve_order(t->params.ecc.sk->curve);

	si_wq_run_after(t, &t->params.ecc.wq, on_generated_private_rnd);

	/* generate private key, a random in [1, n-1], where n is the curve
	 * order
	 */
	si_rndinrange_create(t, (const unsigned char *)curve_n, opsz, t->workmem);

	si_task_run(t);
}

void si_ecc_create_genpubkey(struct sitask *t, const struct si_eccsk *sk, struct si_eccpk *pk)
{
	t->statuscode = SX_ERR_READY;
	t->actions = (struct siactions){0};
	t->actions.run = run_ecc_generate_public_key;
	t->params.ecc.sk = (struct si_eccsk *)sk;
	t->params.ecc.pk = pk;
	t->params.ecc.attempts = MAX_ECC_ATTEMPTS;
	pk->curve = sk->curve;
}

void si_ecc_create_genprivkey(struct sitask *t, const struct sx_pk_ecurve *curve,
			      struct si_eccsk *sk)
{
	size_t keysz = (size_t)sx_pk_curve_opsize(curve);

	int opsz = sx_pk_curve_opsize(curve);
	const char *curve_n = sx_pk_curve_order(curve);

	/* generate private key, a random in [1, n-1], where n is the curve
	 * order
	 */
	get_random_number_in_range(t, (const unsigned char *)curve_n, opsz, t->workmem);

	si_task_run(t);

        	int opsz = sx_pk_curve_opsize(curve);

	(void)wq;

	if (t->statuscode != SX_OK) {
		return t->statuscode;
	}

	memcpy(t->params.ecc.sk->d, t->workmem, opsz);

	return SX_OK;
}

static bool is_zero_bytestring(char *a, size_t sz) {
    int acc = 0;
    for (size_t i = 0; i < sz; i++) {
        acc |= a[i];
    }
    return !acc;
}

int get_random_number_in_range(const unsigned char *n, size_t nsz, unsigned char *out) {
    size_t index;
    unsigned char msb_mask = MSB_MASK_INIT;

    // Check if provided upper limit n has size 0
    if (nsz == 0) {
        return SX_ERR_INPUT_BUFFER_TOO_SMALL;
    }

    // Find index of the most significant non-zero byte in n
    for (index = 0; (n[index] == 0) && (index < nsz); index++) {
        // Empty loop body
    }

    // If the upper limit is 0 or less than 3, return error
    if ((index == nsz) || ((index == nsz - 1) && (n[index] < 3))) {
        return SX_ERR_INPUT_BUFFER_TOO_SMALL;
    }

    // Ensure the provided upper limit is odd
    if ((n[nsz - 1] & 0x01) == 0) {
        return SX_ERR_INVALID_ARG;
    }

    // Generate bit mask for most significant non-zero byte in n
    for (; n[index] & msb_mask; msb_mask <<= 1) {
        // Adjust the mask
    }
    msb_mask = ~msb_mask;

    size_t rndsz = nsz - index;
    unsigned char *adjusted_out = out + index;

    // Initialize high-order zero bytes for the output buffer
    memset(out, 0, index);

    bool valid_number = false;

    while (!valid_number) {
        // Get random bytes
        psa_status_t status = cracen_get_random(NULL, adjusted_out, rndsz);
        if (status != PSA_SUCCESS) {
            return SX_ERR_UNKNOWN_ERROR;
        }

        // Set to zero excess high-order bits in the most significant byte
        adjusted_out[0] &= msb_mask;

        bool is_zero = is_zero_bytestring((char *)adjusted_out, rndsz);
        int ge = si_be_cmp(adjusted_out, n + index, rndsz, 0);

        // Check if the generated number is valid
        if (!is_zero && ge < 0) {
            valid_number = true;
        }
    }

    return SX_OK;
}