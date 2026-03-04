# Copyright (c) 2024 Nordic Semiconductor ASA
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

zephyr_library_sources(
  ${ZEPHYR_BASE}/soc/nordic/nrf54l/soc.c
  ${ZEPHYR_BASE}/soc/nordic/validate_rram_partitions.c
  )

zephyr_include_directories(${ZEPHYR_BASE}/soc/nordic/nrf54l)
add_subdirectory(${ZEPHYR_BASE}/soc/nordic/common ${CMAKE_BINARY_DIR}/common)

zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LS05B NRF54LS05B_XXAA)
zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LS05B_CPUAPP NRF_APPLICATION)

zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LV10A NRF_SKIP_TAMPC_SETUP)
zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LV10A NRF54LV10A_XXAA)
zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LV10A_CPUAPP  NRF_APPLICATION)
zephyr_compile_definitions_ifdef(CONFIG_SOC_NRF54LV10A_CPUFLPR NRF_FLPR)
