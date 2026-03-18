/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * Step 9 — End product tests (placeholder).
 *
 * This step is intentionally left as a stub. Manufacturers should replace or
 * extend tests_step9_run() with their own end-of-line validation logic.
 *
 * Examples of what to add here:
 *
 *   - Automatic hardware self-tests (ADC calibration check, RF power
 *     measurement, sensor validation, UART loopback, etc.).
 *
 *   - Manual test gate: if the device must be tested by an operator before
 *     provisioning is finalised, add code that waits for an external event:
 *
 *       // Wait for PASS signal on UART:
 *       char c = uart_poll_in(...);
 *       if (c != 'P') { ... fail ... }
 *
 *       // Or wait for a button press:
 *       while (!gpio_pin_get(GPIO_PIN)) { k_sleep(K_MSEC(10)); }
 *
 *   - Communication with a test jig over I2C/SPI/UART to exchange test
 *     vectors and receive a PASS/FAIL verdict.
 *
 * The manufacturing application is fully authenticated at this stage (keys
 * provisioned in Step 4), so it is safe to establish trusted communication
 * with external test equipment if needed.
 */

#include "product_tests.h"
#include "mfg_log.h"

void tests_step9_run(void)
{
	MFG_LOG_STEP("End product tests");

	MFG_LOG_INF("This is a good place to add code for end product automatic tests.\n");
	MFG_LOG_INF("If the device shall be tested manually, add code waiting for an external event\n");
	MFG_LOG_INF("(message via serial port, key press or whatever is suitable for your device).\n");
}
