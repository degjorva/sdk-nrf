#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(ikg_personalization)

target_sources(app PRIVATE src/main.c)

# Intercept the CRACEN driver's IKG key derivation so the personalization
# string can be selected at runtime.
zephyr_link_libraries(-Wl,--wrap=cracen_prepare_ik_key)
