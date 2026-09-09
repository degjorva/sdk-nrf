/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <psa/crypto.h>
#include <cracen_hybrid_verify.h>
#include <cracen/statuscodes.h>
#include <internal/ecc/cracen_ecdsa.h>
#include <silexpk/ec_curves.h>
#include <sxsymcrypt/hashdefs.h>
#include <string.h>

#include "ml_dsa_vectors.h"

#define BENCHMARK_ITERATIONS 10

static psa_key_id_t ml_dsa_65_key_id;
static psa_key_id_t ml_dsa_87_key_id;

/*
 * P-384 public key for private scalar d = 2. The signature covers
 * ml_dsa_kat_msg.
 */
static const uint8_t ecdsa_public_key[CRACEN_HYBRID_ECDSA_PUBLIC_KEY_SIZE] = {
	0x08, 0xd9, 0x99, 0x05, 0x7b, 0xa3, 0xd2, 0xd9, 0x69, 0x26, 0x00, 0x45,
	0xc5, 0x5b, 0x97, 0xf0, 0x89, 0x02, 0x59, 0x59, 0xa6, 0xf4, 0x34, 0xd6,
	0x51, 0xd2, 0x07, 0xd1, 0x9f, 0xb9, 0x6e, 0x9e, 0x4f, 0xe0, 0xe8, 0x6e,
	0xbe, 0x0e, 0x64, 0xf8, 0x5b, 0x96, 0xa9, 0xc7, 0x52, 0x95, 0xdf, 0x61,
	0x8e, 0x80, 0xf1, 0xfa, 0x5b, 0x1b, 0x3c, 0xed, 0xb7, 0xbf, 0xe8, 0xdf,
	0xfd, 0x6d, 0xba, 0x74, 0xb2, 0x75, 0xd8, 0x75, 0xbc, 0x6c, 0xc4, 0x3e,
	0x90, 0x4e, 0x50, 0x5f, 0x25, 0x6a, 0xb4, 0x25, 0x5f, 0xfd, 0x43, 0xe9,
	0x4d, 0x39, 0xe2, 0x2d, 0x61, 0x50, 0x1e, 0x70, 0x0a, 0x94, 0x0e, 0x80,
};
static const uint8_t ecdsa_signature[CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE] = {
	0x5b, 0x04, 0xf1, 0x48, 0xf1, 0xda, 0x50, 0x51, 0xbb, 0xbe, 0xac, 0x5b,
	0xe9, 0xde, 0x94, 0x54, 0x63, 0x22, 0x1c, 0x5e, 0x16, 0xab, 0x48, 0x32,
	0xf3, 0x58, 0x6a, 0xb7, 0x47, 0x90, 0xdb, 0xd5, 0xe0, 0x94, 0x2a, 0x5b,
	0x76, 0x11, 0xe4, 0x79, 0x96, 0xdd, 0x5c, 0x97, 0x62, 0x33, 0xec, 0x71,
	0x49, 0x4e, 0x44, 0x75, 0x97, 0x3b, 0xe0, 0xda, 0x51, 0xc7, 0xfb, 0x7f,
	0xc5, 0xc7, 0xa6, 0x4d, 0x7c, 0x9b, 0x7d, 0xc3, 0x5b, 0xfa, 0x38, 0x1b,
	0x01, 0x96, 0x8f, 0x58, 0x34, 0x17, 0xee, 0x84, 0x59, 0x56, 0x94, 0x37,
	0x42, 0xd4, 0xa1, 0xf4, 0xf9, 0xc1, 0x7b, 0x16, 0x50, 0x89, 0x6d, 0xba,
};

/* P-384 signature using the same private scalar, covering ml_dsa87_kat_msg. */
static const uint8_t ecdsa_signature_87[CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE] = {
	0x42, 0x0b, 0x02, 0x45, 0xa2, 0x81, 0xad, 0xd3, 0x04, 0x37, 0x1e, 0x18,
	0x33, 0x8d, 0x9b, 0x84, 0x39, 0x61, 0xb7, 0x66, 0x0a, 0x41, 0x16, 0xe7,
	0x16, 0x56, 0xb2, 0x3f, 0xbf, 0xe0, 0xec, 0x70, 0xcf, 0x0c, 0xfe, 0x15,
	0x91, 0x30, 0x8e, 0xb9, 0xaa, 0xdf, 0xfd, 0xb4, 0xbc, 0x85, 0x2f, 0x85,
	0xac, 0xb6, 0x91, 0x37, 0xa4, 0x0f, 0x79, 0xd5, 0x5b, 0x7d, 0x13, 0x8a,
	0x84, 0x90, 0x04, 0xf1, 0xea, 0x42, 0x0b, 0xab, 0x95, 0x61, 0x1c, 0xb7,
	0x36, 0xc6, 0x70, 0x21, 0x63, 0x4a, 0x31, 0xb4, 0x15, 0x0b, 0x5d, 0x35,
	0xa0, 0x72, 0xaa, 0xc6, 0xe6, 0x6d, 0xe6, 0x8a, 0xd6, 0x9f, 0xc3, 0x84,
};

static psa_key_id_t import_ml_dsa_public_key(const uint8_t *public_key,
					     size_t public_key_length)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_status_t status;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ML_DSA);

	status = psa_import_key(&attributes, public_key, public_key_length, &key_id);
	psa_reset_key_attributes(&attributes);
	zassert_equal(status, PSA_SUCCESS, "ML-DSA public-key import failed: %d", status);

	return key_id;
}

static void *setup_crypto(void)
{
	psa_status_t status = psa_crypto_init();

	zassert_equal(status, PSA_SUCCESS, "PSA Crypto initialization failed: %d", status);
	ml_dsa_65_key_id = import_ml_dsa_public_key(ml_dsa_kat_pk, sizeof(ml_dsa_kat_pk));
	ml_dsa_87_key_id = import_ml_dsa_public_key(ml_dsa87_kat_pk,
						    sizeof(ml_dsa87_kat_pk));

	return NULL;
}

static void teardown_crypto(void *fixture)
{
	ARG_UNUSED(fixture);

	if (ml_dsa_65_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(ml_dsa_65_key_id);
	}
	if (ml_dsa_87_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(ml_dsa_87_key_id);
	}
}

static enum cracen_hybrid_verify_status run_hybrid(
	const uint8_t *ml_dsa_signature, size_t ml_dsa_signature_length,
	const uint8_t *test_ecdsa_signature, size_t ecdsa_signature_length,
	struct cracen_hybrid_verify_result *result)
{
	return cracen_hybrid_verify(
		ml_dsa_kat_msg, sizeof(ml_dsa_kat_msg),
		ml_dsa_kat_pk, sizeof(ml_dsa_kat_pk),
		ml_dsa_signature, ml_dsa_signature_length,
		ecdsa_public_key, sizeof(ecdsa_public_key),
		test_ecdsa_signature, ecdsa_signature_length, result);
}

static int verify_ecdsa(const uint8_t *message, size_t message_length,
			const uint8_t *signature)
{
	return cracen_ecdsa_verify_message(
		ecdsa_public_key, &sxhashalg_sha2_384,
		message, message_length, &sx_curve_nistp384, signature);
}

static psa_status_t verify_ml_dsa(psa_key_id_t key_id, const uint8_t *message,
				  size_t message_length, const uint8_t *signature,
				  size_t signature_length)
{
	return psa_verify_message(key_id, PSA_ALG_ML_DSA, message, message_length,
				  signature, signature_length);
}

ZTEST_SUITE(hybrid_verify, NULL, setup_crypto, NULL, NULL, teardown_crypto);

ZTEST(hybrid_verify, test_valid_signatures)
{
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	status = run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig),
			    ecdsa_signature, sizeof(ecdsa_signature), &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_VALID,
		      "hybrid verify failed: combined=%d ml_dsa=%d ecdsa=%d",
		      result.combined, result.ml_dsa, result.ecdsa);
	zassert_equal(result.combined, CRACEN_HYBRID_VERIFY_VALID, "combined result failed");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_VALID, "ML-DSA result failed");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_VALID, "ECDSA result failed");
}

ZTEST(hybrid_verify, test_valid_ml_dsa_87_signature)
{
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	status = cracen_hybrid_verify(
		ml_dsa87_kat_msg, sizeof(ml_dsa87_kat_msg),
		ml_dsa87_kat_pk, sizeof(ml_dsa87_kat_pk),
		ml_dsa87_kat_sig, sizeof(ml_dsa87_kat_sig),
		ecdsa_public_key, sizeof(ecdsa_public_key),
		ecdsa_signature, sizeof(ecdsa_signature) - 1, &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "unexpected combined result: %d", status);
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_VALID,
		      "valid ML-DSA-87 signature failed");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "unexpected ECDSA result");
}

ZTEST(hybrid_verify, test_invalid_ml_dsa_signature)
{
	uint8_t signature[sizeof(ml_dsa_kat_sig)];
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	memcpy(signature, ml_dsa_kat_sig, sizeof(signature));
	signature[0] ^= 1;
	status = run_hybrid(signature, sizeof(signature), ecdsa_signature,
			    sizeof(ecdsa_signature), &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "invalid ML-DSA signature was accepted");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "unexpected ML-DSA result");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_VALID, "valid ECDSA signature failed");
}

ZTEST(hybrid_verify, test_invalid_ecdsa_signature)
{
	uint8_t signature[sizeof(ecdsa_signature)];
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	memcpy(signature, ecdsa_signature, sizeof(signature));
	signature[0] ^= 1;
	status = run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig),
			    signature, sizeof(signature), &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "invalid ECDSA signature was accepted");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_VALID,
		      "valid ML-DSA signature failed");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "unexpected ECDSA result");
}

ZTEST(hybrid_verify, test_both_signatures_invalid)
{
	uint8_t ml_dsa_signature[sizeof(ml_dsa_kat_sig)];
	uint8_t test_ecdsa_signature[sizeof(ecdsa_signature)];
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	memcpy(ml_dsa_signature, ml_dsa_kat_sig, sizeof(ml_dsa_signature));
	memcpy(test_ecdsa_signature, ecdsa_signature, sizeof(test_ecdsa_signature));
	ml_dsa_signature[0] ^= 1;
	test_ecdsa_signature[0] ^= 1;
	status = run_hybrid(ml_dsa_signature, sizeof(ml_dsa_signature),
			    test_ecdsa_signature, sizeof(test_ecdsa_signature), &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "invalid signatures were accepted");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "unexpected ML-DSA result");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
		      "unexpected ECDSA result");
}

ZTEST(hybrid_verify, test_bad_ecdsa_signature_length)
{
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	status = run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig),
			    ecdsa_signature, sizeof(ecdsa_signature) - 1, &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "bad ECDSA signature length was accepted");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_VALID,
		      "ML-DSA was not evaluated");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "unexpected ECDSA result");
}

ZTEST(hybrid_verify, test_bad_ml_dsa_signature_length)
{
	struct cracen_hybrid_verify_result result;
	enum cracen_hybrid_verify_status status;

	status = run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig) - 1,
			    ecdsa_signature, sizeof(ecdsa_signature), &result);

	zassert_equal(status, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "bad ML-DSA signature length was accepted");
	zassert_equal(result.ml_dsa, CRACEN_HYBRID_VERIFY_INVALID_ARGUMENT,
		      "unexpected ML-DSA result");
	zassert_equal(result.ecdsa, CRACEN_HYBRID_VERIFY_VALID,
		      "ECDSA was not evaluated");
}

ZTEST(hybrid_verify, test_pke_released_after_failure)
{
	uint8_t signature[sizeof(ecdsa_signature)];
	struct cracen_hybrid_verify_result result;

	memcpy(signature, ecdsa_signature, sizeof(signature));
	signature[0] ^= 1;

	for (size_t i = 0; i < 2; i++) {
		zassert_equal(run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig),
					 signature, sizeof(signature), &result),
			      CRACEN_HYBRID_VERIFY_INVALID_SIGNATURE,
			      "invalid iteration %zu returned wrong result", i);
		zassert_equal(run_hybrid(ml_dsa_kat_sig, sizeof(ml_dsa_kat_sig),
					 ecdsa_signature, sizeof(ecdsa_signature), &result),
			      CRACEN_HYBRID_VERIFY_VALID,
			      "valid iteration %zu failed after PKE error", i);
	}
}

struct benchmark_profile {
	const char *name;
	psa_key_id_t key_id;
	const uint8_t *message;
	size_t message_length;
	const uint8_t *ml_dsa_public_key;
	size_t ml_dsa_public_key_length;
	const uint8_t *ml_dsa_signature;
	size_t ml_dsa_signature_length;
	const uint8_t *ecdsa_signature;
};

static void benchmark_profile(const struct benchmark_profile *profile)
{
	struct cracen_hybrid_verify_result result;
	uint64_t ecdsa_cycles = 0;
	uint64_t ml_dsa_cycles = 0;
	uint64_t sequential_cycles = 0;
	uint64_t hybrid_cycles = 0;
	uint64_t ecdsa_average;
	uint64_t ml_dsa_average;
	uint64_t sequential_average;
	uint64_t hybrid_average;
	uint64_t reduction_hundredths;
	size_t unused_stack;
	psa_status_t psa_status;
	enum cracen_hybrid_verify_status hybrid_status;
	int sx_status;

	sx_status = verify_ecdsa(profile->message, profile->message_length,
				profile->ecdsa_signature);
	zassert_equal(sx_status, SX_OK, "ECDSA warm-up failed: %d", sx_status);
	psa_status = verify_ml_dsa(profile->key_id, profile->message, profile->message_length,
				   profile->ml_dsa_signature, profile->ml_dsa_signature_length);
	zassert_equal(psa_status, PSA_SUCCESS, "ML-DSA warm-up failed: %d", psa_status);
	hybrid_status = cracen_hybrid_verify(
		profile->message, profile->message_length,
		profile->ml_dsa_public_key, profile->ml_dsa_public_key_length,
		profile->ml_dsa_signature, profile->ml_dsa_signature_length,
		ecdsa_public_key, sizeof(ecdsa_public_key),
		profile->ecdsa_signature, CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE, &result);
	zassert_equal(hybrid_status, CRACEN_HYBRID_VERIFY_VALID,
		      "hybrid warm-up failed");

	for (size_t i = 0; i < BENCHMARK_ITERATIONS; i++) {
		uint64_t start = k_cycle_get_64();

		sx_status = verify_ecdsa(profile->message, profile->message_length,
					profile->ecdsa_signature);
		ecdsa_cycles += k_cycle_get_64() - start;
		zassert_equal(sx_status, SX_OK, "sequential ECDSA failed: %d", sx_status);

		start = k_cycle_get_64();
		psa_status = verify_ml_dsa(profile->key_id, profile->message,
					   profile->message_length, profile->ml_dsa_signature,
					   profile->ml_dsa_signature_length);
		ml_dsa_cycles += k_cycle_get_64() - start;
		zassert_equal(psa_status, PSA_SUCCESS, "sequential ML-DSA failed: %d",
			      psa_status);

		start = k_cycle_get_64();
		sx_status = verify_ecdsa(profile->message, profile->message_length,
					profile->ecdsa_signature);
		psa_status = verify_ml_dsa(profile->key_id, profile->message,
					   profile->message_length, profile->ml_dsa_signature,
					   profile->ml_dsa_signature_length);
		sequential_cycles += k_cycle_get_64() - start;
		zassert_equal(sx_status, SX_OK, "sequential ECDSA failed: %d", sx_status);
		zassert_equal(psa_status, PSA_SUCCESS, "sequential ML-DSA failed: %d",
			      psa_status);

		start = k_cycle_get_64();
		hybrid_status = cracen_hybrid_verify(
			profile->message, profile->message_length,
			profile->ml_dsa_public_key, profile->ml_dsa_public_key_length,
			profile->ml_dsa_signature, profile->ml_dsa_signature_length,
			ecdsa_public_key, sizeof(ecdsa_public_key),
			profile->ecdsa_signature, CRACEN_HYBRID_ECDSA_SIGNATURE_SIZE, &result);
		hybrid_cycles += k_cycle_get_64() - start;
		zassert_equal(hybrid_status, CRACEN_HYBRID_VERIFY_VALID,
			      "hybrid benchmark failed");
	}

	ecdsa_average = ecdsa_cycles / BENCHMARK_ITERATIONS;
	ml_dsa_average = ml_dsa_cycles / BENCHMARK_ITERATIONS;
	sequential_average = sequential_cycles / BENCHMARK_ITERATIONS;
	hybrid_average = hybrid_cycles / BENCHMARK_ITERATIONS;
	reduction_hundredths = 0;
	if (sequential_average > hybrid_average) {
		reduction_hundredths = (sequential_average - hybrid_average) * 10000 /
				      sequential_average;
	}

	printk("hybrid_verify ML-DSA-%s components: ecdsa_avg_cycles=%llu "
	       "ml_dsa_avg_cycles=%llu\n", profile->name,
	       (unsigned long long)ecdsa_average, (unsigned long long)ml_dsa_average);
	printk("hybrid_verify ML-DSA-%s benchmark: sequential_avg_cycles=%llu "
	       "hybrid_avg_cycles=%llu\n", profile->name,
	       (unsigned long long)sequential_average, (unsigned long long)hybrid_average);
	printk("hybrid_verify ML-DSA-%s benchmark: sequential_avg_us=%llu "
	       "hybrid_avg_us=%llu\n", profile->name,
	       (unsigned long long)k_cyc_to_us_floor64(sequential_average),
	       (unsigned long long)k_cyc_to_us_floor64(hybrid_average));
	printk("hybrid_verify ML-DSA-%s benchmark: reduction=%llu.%02llu%% iterations=%d\n",
	       profile->name,
	       (unsigned long long)(reduction_hundredths / 100),
	       (unsigned long long)(reduction_hundredths % 100), BENCHMARK_ITERATIONS);

	if (k_thread_stack_space_get(k_current_get(), &unused_stack) == 0) {
		printk("hybrid_verify ML-DSA-%s benchmark: unused_test_stack_bytes=%zu\n",
		       profile->name, unused_stack);
	}
}

ZTEST(hybrid_verify, test_benchmark)
{
	const struct benchmark_profile profiles[] = {
		{
			.name = "65",
			.key_id = ml_dsa_65_key_id,
			.message = ml_dsa_kat_msg,
			.message_length = sizeof(ml_dsa_kat_msg),
			.ml_dsa_public_key = ml_dsa_kat_pk,
			.ml_dsa_public_key_length = sizeof(ml_dsa_kat_pk),
			.ml_dsa_signature = ml_dsa_kat_sig,
			.ml_dsa_signature_length = sizeof(ml_dsa_kat_sig),
			.ecdsa_signature = ecdsa_signature,
		},
		{
			.name = "87",
			.key_id = ml_dsa_87_key_id,
			.message = ml_dsa87_kat_msg,
			.message_length = sizeof(ml_dsa87_kat_msg),
			.ml_dsa_public_key = ml_dsa87_kat_pk,
			.ml_dsa_public_key_length = sizeof(ml_dsa87_kat_pk),
			.ml_dsa_signature = ml_dsa87_kat_sig,
			.ml_dsa_signature_length = sizeof(ml_dsa87_kat_sig),
			.ecdsa_signature = ecdsa_signature_87,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(profiles); i++) {
		benchmark_profile(&profiles[i]);
	}
}
