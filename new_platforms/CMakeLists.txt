# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)

project("Open Enclave SDK (New Platforms)" VERSION 0.1 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Declare options
set(OE_TEE "" CACHE STRING
    "Select a Trusted Execution Environment (TEE) implementation.")
set_property(CACHE OE_TEE PROPERTY STRINGS
    "Intel SGX" "SGX" "ARM TrustZone" "TZ")

option(OE_USE_SIMULATION
    "If selected, logic to operate a hardware TEE is replaced with stubs which simulate it, but do not require any."
    OFF)

# Validate and create option shorthands
if("${OE_TEE}" STREQUAL "Intel SGX" OR "${OE_TEE}" STREQUAL "SGX")
    set(SGX ON)
    set(SGX ON PARENT_SCOPE)

    set(TZ OFF)
    set(TZ OFF PARENT_SCOPE)
elseif("${OE_TEE}" STREQUAL "ARM TrustZone" OR "${OE_TEE}" STREQUAL "TZ")
    set(SGX OFF)
    set(SGX OFF PARENT_SCOPE)

    set(TZ ON)
    set(TZ ON PARENT_SCOPE)
else()
    message(FATAL_ERROR "OE_TEE must be one of 'Intel SGX' (shorthand: 'SGX') or 'ARM TrustZone' (shorthand: 'TZ').")
endif()

if(OE_USE_SIMULATION)
    set(SIM ON)
    set(SIM ON PARENT_SCOPE)
else()
    set(SIM OFF)
    set(SIM OFF PARENT_SCOPE)
endif()

if(UNIX AND SGX)
    message(FATAL_ERROR "Intel SGX is not supported on Linux in this preview.")
elseif(UNIX AND TZ AND SIM)
    message(FATAL_ERROR "ARM TrustZone simulation is not supported on Linux in this preview.")
endif()

# Validate target, TEE and toolchain combinations.
if(UNIX AND TZ AND NOT(
    "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm" OR
    "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64"))
    message(FATAL_ERROR "Building for ARM TrustZone requires one of the cross-compiler toolchain failes in the cmake directory; use -DCMAKE_TOOLCHAIN_FILE to specify it.")
endif()

if(WIN32 AND SGX AND ${CMAKE_GENERATOR} MATCHES "ARM")
    message(FATAL_ERROR "Building for Intel SGX is not supported with an ARM generator see (cmake --help).")
endif()

if(WIN32 AND TZ AND NOT SIM AND NOT ${CMAKE_GENERATOR} MATCHES "ARM")
    message(FATAL_ERROR "Building for ARM TrustZone requires an ARM generator (see cmake --help).")
endif()

# Assert that the respective TEE SDK's are present.
if(UNIX AND TZ AND ("$ENV{TA_DEV_KIT_DIR}" STREQUAL "") AND ("${TA_DEV_KIT_DIR}" STREQUAL ""))
    message(FATAL_ERROR "TA_DEV_KIT_DIR must be specified when building for ARM TrustZone.")
elseif(WIN32 AND SGX AND ("$ENV{SGXSDKInstallPath}" STREQUAL "") AND ("${SGXSDKInstallPath}" STREQUAL ""))
    message(FATAL_ERROR "The Intel SGX SDK is required when building for Intel SGX on Windows.")
endif()

# Propagate the environment variables into locals, if necessary.
if(TZ AND (NOT "$ENV{TA_DEV_KIT_DIR}" STREQUAL "") AND ("${TA_DEV_KIT_DIR}" STREQUAL ""))
    set(TA_DEV_KIT_DIR $ENV{TA_DEV_KIT_DIR})
elseif(WIN32 AND SGX)
    find_package(SGXSDK REQUIRED)
elseif(WIN32 AND TZ)
    find_package(WDK REQUIRED)
endif()

find_package(OEEDGER8R REQUIRED)

# Save the path to Open Enclave proper as well as to where the new platform
# support is located. The latter will make it easier to remove all references
# to it once we merge into master.
set(OE_PATH ${PROJECT_SOURCE_DIR}/..)
set(NP_PATH ${PROJECT_SOURCE_DIR})

set(OE_PATH ${OE_PATH} PARENT_SCOPE)
set(NP_PATH ${NP_PATH} PARENT_SCOPE)

# Add 3rd-party path shorthands
set(GTEST_PATH        ${OE_PATH}/3rdparty/googletest)
set(OPTEE_CLIENT_PATH ${OE_PATH}/3rdparty/optee_client)
set(OPTEE_OS_PATH     ${OE_PATH}/3rdparty/optee_os)
set(OPTEE_CALLS_PATH  ${OE_PATH}/3rdparty/OpteeCalls)
set(MBEDTLS_PATH      ${OE_PATH}/3rdparty/mbedtls/mbedtls)
set(RIOT_PATH         ${OE_PATH}/3rdparty/RIoT)
set(CYREP_PATH        ${RIOT_PATH}/CyReP)
set(TINYCBOR_PATH     ${RIOT_PATH}/External/tinycbor)

set(GTEST_PATH        ${GTEST_PATH}        PARENT_SCOPE)
set(OPTEE_CLIENT_PATH ${OPTEE_CLIENT_PATH} PARENT_SCOPE)
set(OPTEE_OS_PATH     ${OPTEE_OS_PATH}     PARENT_SCOPE)
set(OPTEE_CALLS_PATH  ${OPTEE_CALLS_PATH}  PARENT_SCOPE)
set(MBEDTLS_PATH      ${MBEDTLS_PATH}      PARENT_SCOPE)
set(RIOT_PATH         ${RIOT_PATH}         PARENT_SCOPE)
set(CYREP_PATH        ${CYREP_PATH}        PARENT_SCOPE)
set(TINYCBOR_PATH     ${TINYCBOR_PATH}     PARENT_SCOPE)

# Place binaries in predictable locations.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)

# The duplication is so that the add_enclave function can be used by 3rd-party
# consumers of the SDK. The add_enclave function calls into GNU Make and has to
# know the location of the outputs of certain targets. This location is indeed
# CMAKE_*_OUTPUT_DIRECTORY, but the value is different in the scope of a
# consumer from that in the scope of this CMakeLists.txt file and
# subdirectories.
set(OE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(OE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(OE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

set(OE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} PARENT_SCOPE)
set(OE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} PARENT_SCOPE)
set(OE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY} PARENT_SCOPE)

# Add common compiler definitions
if(UNIX)
    add_definitions(-DLINUX)
endif()

if(SGX)
    add_definitions(-DOE_USE_SGX)
else()
    if(SIM)
        add_definitions(-DOE_SIMULATE_OPTEE)
    else()
        add_definitions(-DOE_USE_OPTEE)
    endif()
endif()

# 3rd-party components
add_subdirectory(${MBEDTLS_PATH} ${CMAKE_BINARY_DIR}/out/mbedtls EXCLUDE_FROM_ALL)
if(UNIX AND TZ)
    add_subdirectory(${OPTEE_CLIENT_PATH} ${CMAKE_BINARY_DIR}/out/teec EXCLUDE_FROM_ALL)
endif()

add_subdirectory(libsocket)
add_subdirectory(libstdio)
add_subdirectory(samples)
add_subdirectory(src)
add_subdirectory(tests)

if(WIN32 AND TZ AND SIM)
    add_subdirectory(opteesim)
endif()

if(TZ)
    file(GLOB TA_DEV_KIT
        LIST_DIRECTORIES true
        ${TA_DEV_KIT_DIR}/*)
    file(COPY ${TA_DEV_KIT}
        DESTINATION ${CMAKE_BINARY_DIR}/out/devkit)
endif()
