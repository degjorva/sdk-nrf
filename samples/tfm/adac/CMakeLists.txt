#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

# Configure TF-M to use local PSA-ADAC repository
set(TFM_EXTRA_CONFIG_PATH "${CMAKE_CURRENT_LIST_DIR}/tfm_config.cmake" CACHE PATH "")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(adac)

target_sources(app PRIVATE src/main.c)
