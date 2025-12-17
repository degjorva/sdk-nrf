/*
 * Copyright (c) 2025 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>

int main(void)
{
	printk("Attach the debugger.\n");

	while (1) {
		k_sleep(K_MSEC(1000)); /* You should hit this with your debugger. */

		/* When you are here, you should be able to hit breakpoints in your bootloader.
		 *
		 * To do this, you need to run the following command in the debugger:
		 * - `monitor reset halt` (in gdb)
		 * - `exec monitor reset halt` (in gdb with VSCode)
		 */
	}

	return 0;
}
