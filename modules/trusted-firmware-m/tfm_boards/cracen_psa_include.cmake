#
# Copyright (c) 2026 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

# Resolve the public include directory of the standalone cracen-psa delivery.
#
# This file is included from the TF-M build, where CRACEN_PSA_ROOT and
# ZEPHYR_CRACEN_PSA_MODULE_DIR arrive through the generated config_extra.cmake
# that the ncs-cracen-integration module hands over as TFM_EXTRA_CONFIG_PATH.

if(NOT CRACEN_PSA_INCLUDE_DIR)
  if(CRACEN_PSA_ROOT)
    set(cracen_psa_root ${CRACEN_PSA_ROOT})
  elseif(ZEPHYR_CRACEN_PSA_MODULE_DIR)
    set(cracen_psa_root ${ZEPHYR_CRACEN_PSA_MODULE_DIR})
  else()
    message(FATAL_ERROR
      "Neither CRACEN_PSA_ROOT nor ZEPHYR_CRACEN_PSA_MODULE_DIR is set. The "
      "cracen-psa delivery is required to build the CRACEN TF-M platform.")
  endif()

  set(CRACEN_PSA_INCLUDE_DIR ${cracen_psa_root}/src/cracenpsa/include)

  if(NOT EXISTS ${CRACEN_PSA_INCLUDE_DIR}/cracen_psa_kmu.h)
    message(FATAL_ERROR
      "${CRACEN_PSA_INCLUDE_DIR} does not look like a cracen-psa checkout.")
  endif()
endif()
