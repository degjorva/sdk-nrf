/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file
 * @addtogroup cracen_psa_kmu
 * @{
 * @brief Centralized KMU slot layout management for CRACEN PSA driver.
 *
 * This header provides a centralized, extensible system for managing KMU slot
 * allocations across different devices, protocols, and usage scenarios.
 *
 * The KMU has 256 slots (0-255). This system organizes them into:
 * - Core system slots (fixed, device-independent)
 * - Device-specific reserved ranges (configurable per device)
 * - Protocol/usage-specific ranges (Matter, Thread, Bluetooth, WiFi, etc.)
 * - Application slots (remaining free slots)
 *
 * Device-Specific Adaptations:
 * ---------------------------
 * This system adapts to different devices and feature combinations:
 * - Device-specific defaults: IKG seed slots, bootloader slots can have
 *   device-specific defaults set in Kconfig
 * - Feature-dependent ranges: Slots are only reserved if the feature is enabled
 *   (e.g., IKG seed slots only if CONFIG_CRACEN_IKG_SEED_LOAD is enabled)
 * - Compile-time validation: All slot ranges are validated at build time to
 *   prevent overlaps, regardless of device or feature combination
 *
 * To add device-specific defaults:
 * 1. Add device detection in Kconfig (e.g., "default X if SOC_NRF54L15")
 * 2. The centralized header will use these values automatically
 * 3. Validation will ensure no conflicts with other ranges
 *
 * @note This header must be included after Kconfig values are available.
 */

#ifndef CRACEN_KMU_SLOT_LAYOUT_H
#define CRACEN_KMU_SLOT_LAYOUT_H

#include <zephyr/kernel.h>
#include <zephyr/autoconf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Total number of KMU slots */
#define CRACEN_KMU_TOTAL_SLOTS 256

/* ============================================================================
 * Core System Slots (Fixed, Device-Independent)
 * ============================================================================ */

/**
 * @brief Provisioning slot used to track multi-slot provisioning state.
 *
 * This slot is used internally by the KMU driver to track whether
 * provisioning of multiple consecutive slots is in progress.
 */
#define CRACEN_KMU_PROVISIONING_SLOT 186

/**
 * @brief Protected RAM invalidation data slots.
 *
 * These slots store random data used to invalidate protected RAM after
 * key operations, ensuring key material doesn't persist in protected RAM.
 */
#define CRACEN_KMU_PROT_RAM_INV_SLOT1 248
#define CRACEN_KMU_PROT_RAM_INV_SLOT2 249

/* ============================================================================
 * Device-Specific Reserved Ranges
 * ============================================================================ */

#ifdef CONFIG_CRACEN_IKG_SEED_LOAD
/**
 * @brief IKG seed slot range.
 *
 * The IKG seed spans 3 consecutive slots starting from the configured slot.
 */
#define CRACEN_KMU_IKG_SEED_SLOT_START CONFIG_CRACEN_IKG_SEED_KMU_SLOT
#define CRACEN_KMU_IKG_SEED_SLOT_END   (CONFIG_CRACEN_IKG_SEED_KMU_SLOT + 2)
#else
#define CRACEN_KMU_IKG_SEED_SLOT_START 0
#define CRACEN_KMU_IKG_SEED_SLOT_END   0
#endif

/**
 * @brief Bootloader key slots (device-specific, feature-dependent).
 *
 * Reserved for bootloader public keys. The exact range depends on:
 * 1. Device type (some devices may not use bootloader keys)
 * 2. Feature enablement (CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED)
 * 3. Custom configuration (CONFIG_CRACEN_KMU_BOOTLOADER_SLOT_START/END)
 *
 * Default behavior:
 * - nRF54L series: Enabled by default, slots 226-247
 * - Other devices: Disabled by default
 * - Can be overridden via Kconfig for custom layouts
 */
#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
#define CRACEN_KMU_BOOTLOADER_SLOT_START CONFIG_CRACEN_KMU_BOOTLOADER_SLOT_START
#define CRACEN_KMU_BOOTLOADER_SLOT_END   CONFIG_CRACEN_KMU_BOOTLOADER_SLOT_END
#else
/* Bootloader slots not enabled, so no slots reserved */
#define CRACEN_KMU_BOOTLOADER_SLOT_START 0
#define CRACEN_KMU_BOOTLOADER_SLOT_END   0
#endif

/* ============================================================================
 * Protocol/Usage-Specific Slot Ranges
 * ============================================================================ */

/**
 * @brief Protocol slot range structure.
 *
 * Each protocol declares its slot requirements using this structure.
 */
struct cracen_kmu_protocol_range {
	/** Protocol name (for debugging/documentation) */
	const char *name;
	/** Starting slot (inclusive) */
	uint8_t start;
	/** Ending slot (exclusive, i.e., last slot + 1) */
	uint8_t end;
	/** Whether this protocol is enabled */
	bool enabled;
};

/* Thread protocol slots */
#ifdef CONFIG_OPENTHREAD_PSA_NVM_BACKEND_KMU
#define CRACEN_KMU_THREAD_SLOT_START CONFIG_OPENTHREAD_KMU_SLOT_START
#define CRACEN_KMU_THREAD_SLOT_END   (CONFIG_OPENTHREAD_KMU_SLOT_START + CONFIG_OPENTHREAD_PSA_ITS_NVM_MAX_KEYS)
#define CRACEN_KMU_THREAD_ENABLED    1
#else
#define CRACEN_KMU_THREAD_SLOT_START 0
#define CRACEN_KMU_THREAD_SLOT_END   0
#define CRACEN_KMU_THREAD_ENABLED    0
#endif

/* Matter protocol slots */
#ifdef CONFIG_CHIP_STORE_KEYS_IN_KMU
/* Device-specific defaults for Matter slot ranges can be set here if needed */
#define CRACEN_KMU_MATTER_SLOT_START CONFIG_CHIP_KMU_SLOT_RANGE_START
#define CRACEN_KMU_MATTER_SLOT_END   CONFIG_CHIP_KMU_SLOT_RANGE_END
#define CRACEN_KMU_MATTER_ENABLED    1
#else
#define CRACEN_KMU_MATTER_SLOT_START 0
#define CRACEN_KMU_MATTER_SLOT_END   0
#define CRACEN_KMU_MATTER_ENABLED    0
#endif

/* Bluetooth protocol slots (reserved for future use) */
#ifdef CONFIG_CRACEN_KMU_BLUETOOTH_SLOTS
#define CRACEN_KMU_BLUETOOTH_SLOT_START CONFIG_CRACEN_KMU_BLUETOOTH_SLOT_START
#define CRACEN_KMU_BLUETOOTH_SLOT_END   CONFIG_CRACEN_KMU_BLUETOOTH_SLOT_END
#define CRACEN_KMU_BLUETOOTH_ENABLED   1
#else
#define CRACEN_KMU_BLUETOOTH_SLOT_START 0
#define CRACEN_KMU_BLUETOOTH_SLOT_END   0
#define CRACEN_KMU_BLUETOOTH_ENABLED   0
#endif

/* WiFi protocol slots (reserved for future use) */
#ifdef CONFIG_CRACEN_KMU_WIFI_SLOTS
#define CRACEN_KMU_WIFI_SLOT_START CONFIG_CRACEN_KMU_WIFI_SLOT_START
#define CRACEN_KMU_WIFI_SLOT_END   CONFIG_CRACEN_KMU_WIFI_SLOT_END
#define CRACEN_KMU_WIFI_ENABLED    1
#else
#define CRACEN_KMU_WIFI_SLOT_START 0
#define CRACEN_KMU_WIFI_SLOT_END   0
#define CRACEN_KMU_WIFI_ENABLED    0
#endif

/* ============================================================================
 * Compile-Time Validation
 * ============================================================================ */

/**
 * @brief Check if a slot range is valid (within 0-255 and start < end).
 */
#define CRACEN_KMU_VALIDATE_RANGE(start, end, name) \
	BUILD_ASSERT((start) < (end) && (end) <= CRACEN_KMU_TOTAL_SLOTS, \
		     "Invalid " name " slot range: [" #start ", " #end ")")

/**
 * @brief Check if two ranges overlap.
 */
#define CRACEN_KMU_CHECK_OVERLAP(start1, end1, name1, start2, end2, name2) \
	BUILD_ASSERT(!((start1) < (end2) && (start2) < (end1)), \
		     "Slot range overlap: " name1 " [" #start1 ", " #end1 ") " \
		     "overlaps with " name2 " [" #start2 ", " #end2 ")")

/**
 * @brief Validate a protocol range if enabled.
 * 
 * This macro validates the range only if the protocol is enabled.
 * Uses BUILD_ASSERT with a conditional expression that evaluates to true
 * if the protocol is disabled, or validates the range if enabled.
 */
#define CRACEN_KMU_VALIDATE_PROTOCOL(start, end, enabled, name) \
	BUILD_ASSERT(!(enabled) || ((start) < (end) && (end) <= CRACEN_KMU_TOTAL_SLOTS), \
		     "Invalid " name " slot range: [" #start ", " #end ")")

/* Validate core system slots */
CRACEN_KMU_VALIDATE_RANGE(CRACEN_KMU_PROVISIONING_SLOT, \
			   CRACEN_KMU_PROVISIONING_SLOT + 1, \
			   "provisioning");
CRACEN_KMU_VALIDATE_RANGE(CRACEN_KMU_PROT_RAM_INV_SLOT1, \
			   CRACEN_KMU_PROT_RAM_INV_SLOT2 + 1, \
			   "protected RAM invalidation");

/* Validate device-specific ranges if enabled */
#ifdef CONFIG_CRACEN_IKG_SEED_LOAD
CRACEN_KMU_VALIDATE_RANGE(CRACEN_KMU_IKG_SEED_SLOT_START, \
			   CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			   "IKG seed");
#endif

/* Validate bootloader slots if enabled */
#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
/* Validate bootloader slots only if enabled */
#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
CRACEN_KMU_VALIDATE_RANGE(CRACEN_KMU_BOOTLOADER_SLOT_START, \
			   CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			   "bootloader");
#endif
#endif

/* Validate protocol ranges if enabled */
CRACEN_KMU_VALIDATE_PROTOCOL(CRACEN_KMU_THREAD_SLOT_START, \
			     CRACEN_KMU_THREAD_SLOT_END, \
			     CRACEN_KMU_THREAD_ENABLED, \
			     "Thread");

CRACEN_KMU_VALIDATE_PROTOCOL(CRACEN_KMU_MATTER_SLOT_START, \
			     CRACEN_KMU_MATTER_SLOT_END, \
			     CRACEN_KMU_MATTER_ENABLED, \
			     "Matter");

#ifdef CONFIG_CRACEN_KMU_BLUETOOTH_SLOTS
CRACEN_KMU_VALIDATE_PROTOCOL(CRACEN_KMU_BLUETOOTH_SLOT_START, \
			     CRACEN_KMU_BLUETOOTH_SLOT_END, \
			     CRACEN_KMU_BLUETOOTH_ENABLED, \
			     "Bluetooth");
#endif

#ifdef CONFIG_CRACEN_KMU_WIFI_SLOTS
CRACEN_KMU_VALIDATE_PROTOCOL(CRACEN_KMU_WIFI_SLOT_START, \
			     CRACEN_KMU_WIFI_SLOT_END, \
			     CRACEN_KMU_WIFI_ENABLED, \
			     "WiFi");
#endif

/* Check for overlaps between core system slots */
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_PROVISIONING_SLOT, \
			 CRACEN_KMU_PROVISIONING_SLOT + 1, \
			 "provisioning", \
			 CRACEN_KMU_PROT_RAM_INV_SLOT1, \
			 CRACEN_KMU_PROT_RAM_INV_SLOT2 + 1, \
			 "protected RAM invalidation");

/* Check for overlaps between device-specific ranges */
#ifdef CONFIG_CRACEN_IKG_SEED_LOAD
#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_IKG_SEED_SLOT_START, \
			  CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			  "IKG seed", \
			  CRACEN_KMU_BOOTLOADER_SLOT_START, \
			  CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			  "bootloader");
#endif
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_IKG_SEED_SLOT_START, \
			  CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			  "IKG seed", \
			  CRACEN_KMU_PROVISIONING_SLOT, \
			  CRACEN_KMU_PROVISIONING_SLOT + 1, \
			  "provisioning");
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_IKG_SEED_SLOT_START, \
			  CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			  "IKG seed", \
			  CRACEN_KMU_PROT_RAM_INV_SLOT1, \
			  CRACEN_KMU_PROT_RAM_INV_SLOT2 + 1, \
			  "protected RAM invalidation");
#endif

#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
#ifdef CONFIG_CRACEN_KMU_BOOTLOADER_SLOTS_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_BOOTLOADER_SLOT_START, \
			  CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			  "bootloader", \
			  CRACEN_KMU_PROVISIONING_SLOT, \
			  CRACEN_KMU_PROVISIONING_SLOT + 1, \
			  "provisioning");
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_BOOTLOADER_SLOT_START, \
			  CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			  "bootloader", \
			  CRACEN_KMU_PROT_RAM_INV_SLOT1, \
			  CRACEN_KMU_PROT_RAM_INV_SLOT2 + 1, \
			  "protected RAM invalidation");
#endif
#endif

/* Check for overlaps between enabled protocols */
#if CRACEN_KMU_THREAD_ENABLED && CRACEN_KMU_MATTER_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_THREAD_SLOT_START, \
			 CRACEN_KMU_THREAD_SLOT_END, \
			 "Thread", \
			 CRACEN_KMU_MATTER_SLOT_START, \
			 CRACEN_KMU_MATTER_SLOT_END, \
			 "Matter");
#endif

#if CRACEN_KMU_THREAD_ENABLED && CRACEN_KMU_BLUETOOTH_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_THREAD_SLOT_START, \
			 CRACEN_KMU_THREAD_SLOT_END, \
			 "Thread", \
			 CRACEN_KMU_BLUETOOTH_SLOT_START, \
			 CRACEN_KMU_BLUETOOTH_SLOT_END, \
			 "Bluetooth");
#endif

#if CRACEN_KMU_THREAD_ENABLED && CRACEN_KMU_WIFI_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_THREAD_SLOT_START, \
			 CRACEN_KMU_THREAD_SLOT_END, \
			 "Thread", \
			 CRACEN_KMU_WIFI_SLOT_START, \
			 CRACEN_KMU_WIFI_SLOT_END, \
			 "WiFi");
#endif

#if CRACEN_KMU_MATTER_ENABLED && CRACEN_KMU_BLUETOOTH_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_MATTER_SLOT_START, \
			 CRACEN_KMU_MATTER_SLOT_END, \
			 "Matter", \
			 CRACEN_KMU_BLUETOOTH_SLOT_START, \
			 CRACEN_KMU_BLUETOOTH_SLOT_END, \
			 "Bluetooth");
#endif

#if CRACEN_KMU_MATTER_ENABLED && CRACEN_KMU_WIFI_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_MATTER_SLOT_START, \
			 CRACEN_KMU_MATTER_SLOT_END, \
			 "Matter", \
			 CRACEN_KMU_WIFI_SLOT_START, \
			 CRACEN_KMU_WIFI_SLOT_END, \
			 "WiFi");
#endif

#if CRACEN_KMU_BLUETOOTH_ENABLED && CRACEN_KMU_WIFI_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_BLUETOOTH_SLOT_START, \
			 CRACEN_KMU_BLUETOOTH_SLOT_END, \
			 "Bluetooth", \
			 CRACEN_KMU_WIFI_SLOT_START, \
			 CRACEN_KMU_WIFI_SLOT_END, \
			 "WiFi");
#endif

/* Check protocol overlaps with device-specific ranges */
#ifdef CONFIG_CRACEN_IKG_SEED_LOAD
#if CRACEN_KMU_THREAD_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_THREAD_SLOT_START, \
			  CRACEN_KMU_THREAD_SLOT_END, \
			  "Thread", \
			  CRACEN_KMU_IKG_SEED_SLOT_START, \
			  CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			  "IKG seed");
#endif
#if CRACEN_KMU_MATTER_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_MATTER_SLOT_START, \
			  CRACEN_KMU_MATTER_SLOT_END, \
			  "Matter", \
			  CRACEN_KMU_IKG_SEED_SLOT_START, \
			  CRACEN_KMU_IKG_SEED_SLOT_END + 1, \
			  "IKG seed");
#endif
#endif

#if CRACEN_KMU_THREAD_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_THREAD_SLOT_START, \
			 CRACEN_KMU_THREAD_SLOT_END, \
			 "Thread", \
			 CRACEN_KMU_BOOTLOADER_SLOT_START, \
			 CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			 "bootloader");
#endif

#if CRACEN_KMU_MATTER_ENABLED
CRACEN_KMU_CHECK_OVERLAP(CRACEN_KMU_MATTER_SLOT_START, \
			 CRACEN_KMU_MATTER_SLOT_END, \
			 "Matter", \
			 CRACEN_KMU_BOOTLOADER_SLOT_START, \
			 CRACEN_KMU_BOOTLOADER_SLOT_END + 1, \
			 "bootloader");
#endif

/* ============================================================================
 * Helper Macros for Backward Compatibility
 * ============================================================================ */

/**
 * @brief Legacy define for provisioning slot (backward compatibility).
 * @deprecated Use CRACEN_KMU_PROVISIONING_SLOT instead.
 */
#define PROVISIONING_SLOT CRACEN_KMU_PROVISIONING_SLOT

/**
 * @brief Legacy defines for protected RAM invalidation slots (backward compatibility).
 * @deprecated Use CRACEN_KMU_PROT_RAM_INV_SLOT1/2 instead.
 */
#define PROTECTED_RAM_INVALIDATION_DATA_SLOT1 CRACEN_KMU_PROT_RAM_INV_SLOT1
#define PROTECTED_RAM_INVALIDATION_DATA_SLOT2 CRACEN_KMU_PROT_RAM_INV_SLOT2

#ifdef __cplusplus
}
#endif

#endif /* CRACEN_KMU_SLOT_LAYOUT_H */

/** @} */
