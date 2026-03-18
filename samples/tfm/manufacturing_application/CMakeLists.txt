#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(manufacturing_application)

# Generate C headers from PEM key files and binary verification message files
# in the keys/ directory. The generated header is placed in
# ${CMAKE_BINARY_DIR}/generated/provisioned_keys.h
include(cmake/keys.cmake)

# NORDIC SDK APP START
target_sources(app PRIVATE
  src/main.c
  src/recovery.c
  src/lcs.c
  src/ikg_check.c
  src/image_validation.c
  src/key_provisioning.c
  src/erase_protection.c
  src/huk_provisioning.c
  src/product_tests.c
  src/asset_provisioning.c
)
# NORDIC SDK APP END

target_include_directories(app PRIVATE
  # TF-M NS API headers (psa/crypto.h, psa/lifecycle.h, etc.)
  $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
  # Application source directory (for mfg_log.h, step headers)
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  # Build-time generated headers (provisioned_keys.h, image_digests.h)
  ${CMAKE_BINARY_DIR}/generated
)
