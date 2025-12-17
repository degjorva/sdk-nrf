# TF-M configuration overrides for ADAC sample
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

set(PLATFORM_PSA_ADAC_SECURE_DEBUG TRUE CACHE BOOL "Enable PSA-ADAC secure debug" FORCE)

# Use west-managed PSA-ADAC repository (modules/tee/tf-m/psa-adac)
# This prevents TF-M's FetchContent from downloading it
get_filename_component(PSA_ADAC_LOCAL_PATH
    "${CMAKE_CURRENT_LIST_DIR}/../../../../modules/tee/tf-m/psa-adac" ABSOLUTE)
if(EXISTS "${PSA_ADAC_LOCAL_PATH}")
    set(PLATFORM_PSA_ADAC_SOURCE_PATH "${PSA_ADAC_LOCAL_PATH}" CACHE PATH "Path to psa-adac" FORCE)
    set(FETCHCONTENT_SOURCE_DIR_LIBPSAADAC "${PSA_ADAC_LOCAL_PATH}" CACHE PATH "" FORCE)
endif()
