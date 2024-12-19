/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * The comments in this file use the notations and conventions from RFC 8032.
 *
 * Workmem layout for an Ed25519 signature verification task:
 *      1. digest (size: 64 bytes).
 *
 * Workmem layout for an Ed25519 signature generation task:
 *      The workmem is made of 5 areas of 32 bytes each (total size 160 bytes).
 *      In the following we refer to these areas using the numbers 1 to 5. The
 *      first hash operation computes the private key's digest, which is stored
 *      in areas 1 and 2. The second hash operation computes r, which is stored
 *      in areas 4 and 5. The first point multiplication computes R, which is
 *      written directly to the output buffer. Then the secret scalar s is
 *      computed in place in area 1. Area 2 is cleared. The second point
 *      multiplication computes the public key A, which is stored in area 2. The
 *      third hash operation computes k, which is stored in areas 2 and 3. The
 *      final operation (r + k * s) mod L computes S, which is written directly
 *      to the output buffer.
 *
 * Workmem layout for an Ed25519 public key generation task:
 *      1. digest (size: 64 bytes). The digest of the private key is written in
 *         this area. Then the secret scalar s is computed in place in the first
 *         32 bytes of this area.
 */
#include <string.h>
#include <sxsymcrypt/sha2.h>
#include <silexpk/ed25519.h>
#include <cracen/ec_helpers.h>
#include <sxsymcrypt/hash.h>
#include <cracen/mem_helpers.h>
#include <cracen/statuscodes.h>

#define DOM2_SIZE 34

int hash_all_inputs(const char *inputs[], size_t *inputs_lengths[], size_t inputs_count,
		    const struct sxhashalg *hashalg, char *out)
{
	struct sxhash hashopctx;
	int status;

	status = sx_hash_create(&hashopctx, hashalg, sizeof(hashopctx));
	if (status != SX_OK) {
		return status;
	}
	for (int i = 0; i < inputs_count; i++) {
		status = sx_hash_feed(&hashopctx, inputs[i], *inputs_lengths[i]);
		if (status != SX_OK) {
			return status;
		}
	}

	status = sx_hash_digest(&hashopctx, out);
	if (status != SX_OK) {
		return status;
	}
	status = sx_hash_wait(&hashopctx);

	return status;
}

static int ed25519_hash_message(const char *message, size_t message_length, char *digest)
{
	const char *hash_array[] = {(char *)message};
	size_t *hash_array_lengths[] = {&message_length};

	return hash_all_inputs(hash_array, hash_array_lengths, 1, &sxhashalg_sha2_512, digest);
}

static int ed25519_hash_privkey(char *workmem, const uint8_t *priv_key)
{
	/* Hash the private key, the digest is stored in the first 64 bytes of workmem */
	const char *hash_array[] = {(char *)priv_key};
	size_t priv_key_length = SX_ED25519_SZ;
	size_t *hash_array_lengths[] = {&priv_key_length};

	return hash_all_inputs(hash_array, hash_array_lengths, 1, &sxhashalg_sha2_512, workmem);
}

static int ed25519_calculate_r(char *workmem, const uint8_t *message, size_t message_length,
			       bool prehash)
{
	const char *hash_array[3];
	size_t *hash_array_lengths[3];
	size_t point_r_sz = SX_ED25519_SZ;
	size_t input_count = 2;

	if (prehash) {
		/* This is the ASCII string with the
		 * PHflag 1 and context size 0 appended as defined in:
		 * https://datatracker.ietf.org/doc/html/rfc8032.html#section-2
		 * used for domain seperation between Ed25519 and Ed25519ph.
		 * This can not be stored as a const due to hardware limitations
		 */
		char dom2[] = {0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
			       0x39, 0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35,
			       0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69,
			       0x73, 0x69, 0x6f, 0x6e, 0x73, 0x01, 0x00};
		size_t dom2sz = sizeof(dom2);

		input_count = 3;

		hash_array[0] = (char *)dom2;
		hash_array_lengths[0] = &dom2sz;
	}
	hash_array[input_count - 2] = workmem + SX_ED25519_SZ;
	hash_array_lengths[input_count - 2] = &point_r_sz;
	hash_array[input_count - 1] = (char *)message;
	hash_array_lengths[input_count - 1] = &message_length;

	return hash_all_inputs(hash_array, hash_array_lengths, input_count, &sxhashalg_sha2_512,
			       workmem + 3 * SX_ED25519_SZ);
}

static int ed25519_calculate_k(char *workmem, char *point_r, const char *message,
			       size_t message_length, int prehash)
{
	const char *hash_array[3];
	size_t *hash_array_lengths[3];
	size_t point_r_sz = SX_ED25519_SZ;
	size_t input_count = prehash ? 4 : 3;

	if (prehash) {
		/* This is the ASCII string with the
		 * PHflag 1 and context size 0 appended as defined in:
		 * https://datatracker.ietf.org/doc/html/rfc8032.html#section-2
		 * used for domain seperation between Ed25519 and Ed25519ph.
		 * This can not be stored as a const due to hardware limitations
		 */
		char dom2[] = {0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
			       0x39, 0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35,
			       0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69,
			       0x73, 0x69, 0x6f, 0x6e, 0x73, 0x01, 0x00};

		size_t dom2sz = sizeof(dom2);

		hash_array[0] = (char *)dom2;
		hash_array_lengths[0] = &dom2sz;
	}

	hash_array[input_count - 3] = point_r;
	hash_array_lengths[input_count - 3] = &point_r_sz;
	hash_array[input_count - 2] = workmem + SX_ED25519_SZ;
	hash_array_lengths[input_count - 2] = &point_r_sz;
	hash_array[input_count - 1] = (char *)message;
	hash_array_lengths[input_count - 1] = &message_length;

	return hash_all_inputs(hash_array, hash_array_lengths, input_count, &sxhashalg_sha2_512,
			       workmem + SX_ED25519_SZ);
}
int ed25519_sign_internal(const uint8_t *priv_key, char *signature, const uint8_t *message,
			  size_t message_length, int prehash)
{
	int status;
	char workmem[5 * SX_ED25519_SZ];
	uint8_t pnt_r[SX_ED25519_DGST_SZ];
	char *area_1 = workmem;
	char *area_2 = workmem + 1 * SX_ED25519_SZ;
	char *area_4 = workmem + 3 * SX_ED25519_SZ;

	/*Hash the private key, the digest is stored in the first 64 bytes of workmem*/
	status = ed25519_hash_privkey(area_1, priv_key);
	if (status != SX_OK) {
		return status;
	}
	/* Obtain r by hashing (prefix || message), where prefix is the second
	 * half of the private key digest.
	 */
	status = ed25519_calculate_r(area_1, message, message_length, true);
	if (status != SX_OK) {
		return status;
	}
	/* Perform point multiplication R = [r]B. This is the encoded point R,
	 * which is the first part of the signature.
	 */
	status = sx_ed25519_ptmult((const struct sx_ed25519_dgst *)area_4,
				   (struct sx_ed25519_pt *)pnt_r);
	if (status != SX_OK) {
		return status;
	}
	/* The secret scalar s is computed in place from the first half of the
	 * private key digest.
	 */
	decode_scalar_25519(area_1);

	/* Clear second half of private key digest: sx_ed25519_ptmult()
	 * works on an input of SX_ED25519_DGST_SZ bytes.
	 */
	safe_memset(area_2, sizeof(workmem) - SX_ED25519_SZ, 0, SX_ED25519_SZ);
	/* Perform point multiplication A = [s]B,
	 * to obtain the public key A. which is stored in workmem[32:63]
	 */
	status = sx_ed25519_ptmult((const struct sx_ed25519_dgst *)(char *)area_1,
				   (struct sx_ed25519_pt *)(struct sx_ed25519_pt *)(char *)area_2);

	if (status != SX_OK) {
		return status;
	}

	status = ed25519_calculate_k(area_1, pnt_r, message, message_length, prehash);
	if (status != SX_OK) {
		return status;
	}

	/* Compute (r + k * s) mod L. This gives the second part of the
	 * signature, which is the encoded S which is stored in pnt_r.
	 */

	status = sx_ed25519_sign((const struct sx_ed25519_dgst *)(area_2),
				 (const struct sx_ed25519_dgst *)(area_4),
				 (const struct sx_ed25519_v *)area_1,
				 (struct sx_ed25519_v *)(pnt_r + SX_ED25519_PT_SZ));
	if (status != SX_OK) {
		return status;
	}

	memcpy(signature, pnt_r, SX_ED25519_DGST_SZ);

	return status;
}
int cracen_ed25519_sign(const uint8_t *priv_key, char *signature, const uint8_t *message,
			size_t message_length)
{
	return ed25519_sign_internal(priv_key, signature, message, message_length, 0);
}

int cracen_ed25519ph_sign(const uint8_t *priv_key, char *signature, const uint8_t *message,
			  size_t message_length, int ismessage)
{
	char hashedmessage[SX_ED25519_DGST_SZ];
	int status;

	if (ismessage) {
		status = ed25519_hash_message(message, message_length, hashedmessage);
		if (status != SX_OK) {
			return status;
		}
		return ed25519_sign_internal(priv_key, signature, hashedmessage, SX_ED25519_DGST_SZ,
					     true);
	} else {
		return ed25519_sign_internal(priv_key, signature, message, message_length, true);
	}
}

static int ed25519_verify_internal(const uint8_t *pub_key, const char *message,
				   size_t message_length, const char *signature, bool prehash)
{
	int status;
	char digest[SX_ED25519_DGST_SZ];
	size_t ed25519_sz = SX_ED25519_SZ;

	const char *hash_array[] = { (char *)signature, (char *)pub_key, (char *)message};
	size_t *hash_array_lengths[] = {&ed25519_sz, &ed25519_sz, &message_length};

	status = hash_all_inputs(hash_array, hash_array_lengths, 3, &sxhashalg_sha2_512, digest);
	if (status != SX_OK) {
		return status;
	}
	status =
		sx_ed25519_verify((struct sx_ed25519_dgst *)digest, (struct sx_ed25519_pt *)pub_key,
				  (const struct sx_ed25519_v *)(signature + SX_ED25519_SZ),
				  (const struct sx_ed25519_pt *)signature);

	return status;
}

static int ed25519ph_verify_internal(const uint8_t *pub_key, const char *message,
				     size_t message_length, const char *signature, bool prehash)
{
	int status;
	char digest[SX_ED25519_DGST_SZ];
	size_t dom2sz = DOM2_SIZE;
	size_t ed25519_sz = SX_ED25519_SZ;

	/* This is the ASCII string with the
	 * PHflag 1 and context size 0 appended as defined in:
	 * https://datatracker.ietf.org/doc/html/rfc8032.html#section-2
	 * used for domain seperation between Ed25519 and Ed25519ph.
	 * This can not be stored as a const due to hardware limitations
	 */
	char dom2[] = {0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6e,
		       0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f,
		       0x6c, 0x6c, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x01, 0x00};

	const char *hash_array[] = { dom2, (char *)signature, (char *)pub_key, (char *)message};
	size_t *hash_array_lengths[] = {&dom2sz, &ed25519_sz, &ed25519_sz, &message_length};

	status = hash_all_inputs(hash_array, hash_array_lengths, 4, &sxhashalg_sha2_512, digest);
	if (status != SX_OK) {
		return status;
	}
	status =
		sx_ed25519_verify((struct sx_ed25519_dgst *)digest, (struct sx_ed25519_pt *)pub_key,
				  (const struct sx_ed25519_v *)(signature + SX_ED25519_SZ),
				  (const struct sx_ed25519_pt *)signature);

	return status;
}

int cracen_ed25519_verify(const uint8_t *pub_key, const char *message, size_t message_length,
			  const char *signature)
{
	return ed25519_verify_internal(pub_key, message, message_length, signature, false);
}

int cracen_ed25519ph_verify(const uint8_t *pub_key, const char *message, size_t message_length,
			    const char *signature, int ismessage)
{
	int status;
	char message_digest[SX_ED25519_DGST_SZ];

	if (ismessage) {
		status = ed25519_hash_message(message, message_length, message_digest);
		if (status != SX_OK) {
			return status;
		}
		return ed25519ph_verify_internal(pub_key, message_digest, SX_ED25519_DGST_SZ,
						 signature, true);
	}
	return ed25519ph_verify_internal(pub_key, message, message_length, signature, true);
}

int cracen_ed25519_create_pubkey(const uint8_t *priv_key, uint8_t *pub_key)
{
	int status;
	char digest[SX_ED25519_DGST_SZ];
	char *pub_key_A = digest + SX_ED25519_SZ;

	status = ed25519_hash_privkey(digest, priv_key);
	if (status != SX_OK) {
		return status;
	}
	/* The secret scalar s is computed in place from the first half of the
	 * private key digest.
	 */
	decode_scalar_25519(digest);

	/* Clear second half of private key digest: ed25519_ptmult_go()
	 * works on an input of SX_ED25519_DGST_SZ bytes.
	 */
	safe_memset(pub_key_A, SX_ED25519_SZ, 0, SX_ED25519_SZ);

	/* Perform point multiplication A = [s]B, to obtain the public key A. */
	status = sx_ed25519_ptmult(
		(const struct sx_ed25519_dgst *)(digest),
		(struct sx_ed25519_pt *)(struct sx_ed25519_pt *)((char *)pub_key_A));

	if (status != SX_OK) {
		return status;
	}

	memcpy(pub_key, pub_key_A, SX_ED25519_SZ);

	return status;
}
