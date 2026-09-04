#
# Copyright (c) 2025, Nordic Semiconductor ASA.
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

set(NRF_BOARD_SELECTED True)

add_subdirectory(${Trusted\ Firmware\ M_SOURCE_DIR}/platform/ext/target/nordic_nrf/common/nrf54l10 nrf54l10)

add_subdirectory(${TFM_BOARDS_NRF_DIR} tfm_board)

include(${TFM_BOARDS_NRF_DIR}/cracen_psa_include.cmake)

target_include_directories(platform_s
  PUBLIC
  ${CRACEN_PSA_INCLUDE_DIR}
  )

target_sources(platform_s
  PRIVATE
  ${ZEPHYR_BASE}/soc/nordic/nrf54l/soc.c
  )

target_include_directories(platform_s
  PRIVATE
  ${ZEPHYR_BASE}/modules/cmsis/
  ${ZEPHYR_BASE}/soc/nordic/nrf54l
  ${ZEPHYR_BASE}/soc/nordic/common
  )

install(FILES       ${CMAKE_CURRENT_LIST_DIR}/ns/cpuarch_ns.cmake
        DESTINATION ${INSTALL_PLATFORM_NS_DIR}
        RENAME      cpuarch.cmake)

install(FILES       config.cmake
        DESTINATION ${INSTALL_PLATFORM_NS_DIR})

install(FILES       ${TFM_BOARDS_NRF_DIR}/common/config.cmake
        DESTINATION ${INSTALL_PLATFORM_NS_DIR}/../common/)

install(DIRECTORY   ${Trusted\ Firmware\ M_SOURCE_DIR}/platform/ext/target/nordic_nrf/nrf54l15dk_nrf54l10_cpuapp/tests
        DESTINATION ${INSTALL_PLATFORM_NS_DIR}
)
