/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file mfg_log.h
 *
 * Manufacturing application logging macros.
 *
 * The manufacturing application uses printk() directly for user-facing output
 * rather than the Zephyr logging subsystem. This produces clean, undecorated
 * output matching the format specified in the manufacturing flow document,
 * without timestamp prefixes or module-name tags.
 *
 * Two classes of macros are defined:
 *
 * MFG_LOG_STEP(msg)
 *   Emits the "entry log" for each step. Includes the source file path and
 *   line number so operators can locate the corresponding source code, e.g.:
 *     Validating images, nrf/samples/tfm/manufacturing_application/src/image_validation.c, line: 42
 *
 *   NOTE: Call this macro exactly once at the top of each step function so
 *   that __FILE__ and __LINE__ expand to the correct location.
 *
 *   The path shown by __FILE__ depends on the build system. In a west/Zephyr
 *   build, -fmacro-prefix-map strips the absolute workspace root, leaving a
 *   path relative to the NCS root (e.g. nrf/samples/tfm/manufacturing_application/...).
 *
 * MFG_LOG_INF(fmt, ...)
 *   Plain informational output (no prefix).
 *
 * MFG_LOG_ERR(fmt, ...)
 *   Error output.
 */

#ifndef MFG_LOG_H_
#define MFG_LOG_H_

#include <zephyr/sys/printk.h>

/** Entry log — emits step description with source location. */
#define MFG_LOG_STEP(msg) \
	printk("\n" msg ", " __FILE__ ", line: %d\n", __LINE__)

/** Plain informational log line. */
#define MFG_LOG_INF(...) printk(__VA_ARGS__)

/** Error log line. */
#define MFG_LOG_ERR(...) printk(__VA_ARGS__)

#endif /* MFG_LOG_H_ */
