/*
 *  Copyright (c) 2026 Nordic Semiconductor ASA
 *
 *  SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 *  Internal definitions shared between sha3.c and xof.c (the streaming
 *  SHAKE-128/256 XOF). Not a public sxsymcrypt header.
 */

#ifndef SHA3_INTERNAL_HEADER_FILE
#define SHA3_INTERNAL_HEADER_FILE

#include <stddef.h>
#include <stdint.h>

#include <sxsymcrypt/hashdefs.h>

#include "cmdma.h"

/** Byte to be added at the beginning of the padding in SHA3 mode */
#define SHA3_MODE_PREFIX 0x06
/** Byte to be added at the end of the padding in SHA3 mode */
#define SHA3_MODE_SUFFIX 0x80
/** Byte to be added at the beginning of the padding for SHAKE. */
#define SHAKE_MODE_PREFIX 0x1F
/** Byte to be added at the end of the padding for SHAKE. */
#define SHAKE_MODE_SUFFIX 0x80

#define SHA3_SAVE_CONTEXT          (1 << 6)
#define SHA3_SHAKE_ENABLE          (1 << 4)
#define SHA3_MODE(x)               ((x) << 0)
#define SHA3_MODE_SHAKE(x, outlen) ((x) | SHA3_SHAKE_ENABLE | ((outlen) << 8))
#define SHA3_OUTLEN_SHIFT          8
#define SHA3_SW_PAD                0

/** Mode value for SHAKE-128 (rate 168, capacity 32) on the BA418 hash core.
 *
 * The BA418 mode field is 4 bits wide (bits 0-3) and SHA3 production modes
 * are 6 (SHA3-224), 7 (SHA3-256, also SHAKE-256 with SHAKE_ENABLE), 11
 * (SHA3-384), 15 (SHA3-512). SHAKE-128 (rate 168) does not correspond to
 * any SHA3 hash so it gets its own mode value; mode 3 was determined
 * empirically by the cracen_xof ztest on nRF54L15 BA418 r1 silicon (KATs
 * for SHAKE-128("") and SHAKE-128("abc") match FIPS 202). Mode 5 hangs the
 * IP. The other unused mode values (0, 1, 2, 4, 8, 9, 10, 12, 13, 14) have
 * not been tried but are unlikely to encode SHAKE-128.
 *
 * If a future BA418 revision changes this encoding, the cracen_xof ztest
 * will fail at test_shake128_empty_short - that's the canary test for it.
 */
#define SHA3_MODE_SHAKE128 3

extern const struct sx_digesttags ba418tags;

/** SHA3/SHAKE padding according to the standard SHA-3 padding scheme described
 *  in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 *  (section 5.1 and B.2).
 */
size_t sha3_fips202_pad(uint8_t prefix, uint8_t suffix, size_t capacity, size_t msgsz,
			uint8_t *padding);

#endif /* SHA3_INTERNAL_HEADER_FILE */
