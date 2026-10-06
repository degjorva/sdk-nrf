/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/*
 * Compare the CRACEN IKG identity key derived with:
 *   - no personalization string
 *   - a single all-zero 32-bit word (what CONFIG_CRACEN_IKG_PERSONALIZED_KEYS
 *     writes for owner 0)
 *   - an all-zero string of the maximum length the IKG accepts
 *   - a nonzero word (control, must differ)
 *
 * The driver's cracen_prepare_ik_key() is wrapped at link time so the IKG
 * is re-derived with the selected personalization before every IKG op.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <psa/crypto.h>
#include <cracen_psa.h>
#include <silexpk/core.h>
#include <silexpk/ik.h>

#define PUB_KEY_SIZE	  65
#define MAX_PERS_WORDS	  16
#define SX_OK		  0

enum pers_mode {
	PERS_NONE,
	PERS_ZERO_ONE_WORD,
	PERS_ZERO_FULL,
	PERS_NONZERO_CONTROL,
	PERS_NONE_AGAIN,
	PERS_MODE_COUNT,
};

static const char *const mode_names[PERS_MODE_COUNT] = {
	[PERS_NONE] = "no personalization",
	[PERS_ZERO_ONE_WORD] = "1 x 0x00000000",
	[PERS_ZERO_FULL] = "max-length zeros",
	[PERS_NONZERO_CONTROL] = "1 x 0x00000001 (control)",
	[PERS_NONE_AGAIN] = "no personalization (repeat)",
};

struct sx_regs;
struct sx_regs *sx_pk_get_regs(void);
uint32_t sx_pk_rdreg(struct sx_regs *regs, uint32_t addr);

#define IK_REG_HW_CONFIG (0x1000 + 0x2C)

static uint32_t ik_hw_config;
static enum pers_mode current_mode;
static int full_len_words = -1;
static int last_derive_status;

int __real_cracen_prepare_ik_key(const uint8_t *user_data);

int __wrap_cracen_prepare_ik_key(const uint8_t *user_data)
{
	static const uint32_t zeros[MAX_PERS_WORDS];
	static const uint32_t control[1] = {0x00000001};
	struct sx_pk_config_ik cfg = {0};
	int status;

	/* Loads the IKG seed from KMU and derives with the driver default. */
	status = __real_cracen_prepare_ik_key(user_data);
	if (status != SX_OK) {
		last_derive_status = status;
		return status;
	}

	ik_hw_config = sx_pk_rdreg(sx_pk_get_regs(), IK_REG_HW_CONFIG);

	switch (current_mode) {
	case PERS_ZERO_ONE_WORD:
		cfg.key_bundle = zeros;
		cfg.key_bundle_sz = 1;
		break;
	case PERS_ZERO_FULL:
		/* The IKG rejects too long strings before starting, so probe down. */
		cfg.key_bundle = zeros;
		for (int n = MAX_PERS_WORDS; n > 0; n--) {
			cfg.key_bundle_sz = n;
			status = sx_pk_ik_derive_keys(&cfg);
			if (status == SX_OK) {
				full_len_words = n;
				break;
			}
		}
		last_derive_status = status;
		return status;
	case PERS_NONZERO_CONTROL:
		cfg.key_bundle = control;
		cfg.key_bundle_sz = 1;
		break;
	default:
		break;
	}

	status = sx_pk_ik_derive_keys(&cfg);
	last_derive_status = status;
	return status;
}

static void print_hex(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		printk("%02x", buf[i]);
	}
	printk("\n");
}

int main(void)
{
	static uint8_t pub[PERS_MODE_COUNT][PUB_KEY_SIZE];
	psa_status_t status;
	size_t len;
	bool zero1_eq, zero_full_eq, control_diff, repeat_eq;

	printk("IKG personalization comparison\n");

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		printk("psa_crypto_init failed: %d\n", status);
		printk("RESULT: ERROR\n");
		return 0;
	}

	for (int m = 0; m < PERS_MODE_COUNT; m++) {
		current_mode = m;
		status = psa_export_public_key(CRACEN_BUILTIN_IDENTITY_KEY_ID, pub[m],
					       sizeof(pub[m]), &len);
		if (status != PSA_SUCCESS || len != PUB_KEY_SIZE) {
			printk("export (%s) failed: %d (derive %d)\n", mode_names[m], status,
			       last_derive_status);
			printk("RESULT: ERROR\n");
			return 0;
		}
		printk("%-28s: ", mode_names[m]);
		print_hex(pub[m], len);
	}

	printk("max personalization length: %d words\n", full_len_words);
	printk("IK HW_CONFIG 0x%08x: DF %s, pers_sz %u words, nonce_sz %u words\n",
	       ik_hw_config, (ik_hw_config & BIT(12)) ? "enabled" : "disabled",
	       (ik_hw_config >> 24) & 0xF, (ik_hw_config >> 20) & 0xF);

	zero1_eq = memcmp(pub[PERS_NONE], pub[PERS_ZERO_ONE_WORD], PUB_KEY_SIZE) == 0;
	zero_full_eq = memcmp(pub[PERS_NONE], pub[PERS_ZERO_FULL], PUB_KEY_SIZE) == 0;
	control_diff = memcmp(pub[PERS_NONE], pub[PERS_NONZERO_CONTROL], PUB_KEY_SIZE) != 0;
	repeat_eq = memcmp(pub[PERS_NONE], pub[PERS_NONE_AGAIN], PUB_KEY_SIZE) == 0;

	printk("none == 1 x zero word : %s\n", zero1_eq ? "SAME" : "DIFFERENT");
	printk("none == max zeros     : %s\n", zero_full_eq ? "SAME" : "DIFFERENT");
	printk("control differs       : %s\n", control_diff ? "yes" : "NO (personalization ignored?)");
	printk("derivation repeatable : %s\n", repeat_eq ? "yes" : "NO");

	if (!control_diff || !repeat_eq) {
		printk("RESULT: INCONCLUSIVE\n");
	} else {
		printk("RESULT: zero_word=%s zero_full=%s\n", zero1_eq ? "SAME" : "DIFFERENT",
		       zero_full_eq ? "SAME" : "DIFFERENT");
	}

	return 0;
}
