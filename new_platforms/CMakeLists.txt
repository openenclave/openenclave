cmake_minimum_required(VERSION 3.5.1 FATAL_ERROR)

project("Open Enclave SDK (New Platforms)" VERSION 0.1 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Declare options
set(OE_TEE "" CACHE STRING
    "Select a Trusted Execution Environment (TEE) implementation.")
set_property(CACHE OE_TEE PROPERTY STRINGS
    "Intel SGX" "ARM TrustZone")

set(OE_WORD "" CACHE STRING
    "Select whether binaries are built for x86/ARM or x64/AARCH64.")
set_property(CACHE OE_WORD PROPERTY STRINGS
    "32" "64")

option(OE_USE_SIMULATION
    "If selected, logic to operate a hardware TEE is replaced with stubs which simulate it, but do not require any."
    OFF)

# Validate and create option shorthands
if("${OE_TEE}" STREQUAL "Intel SGX")
    set(SGX ON)
    set(TZ OFF)
elseif("${OE_TEE}" STREQUAL "ARM TrustZone")
    set(SGX OFF)
    set(TZ ON)
else()
    message(FATAL_ERROR "OE_TEE must be one of 'Intel SGX' or 'ARM TrustZone'.")
endif()

if(OE_USE_SIMULATION)
    set(SIM ON)
else()
    set(SIM OFF)
endif()

if("${OE_WORD}" STREQUAL "32")
    set(WS32 ON)
    set(WS64 OFF)
elseif("${OE_WORD}" STREQUAL "64")
    set(WS32 OFF)
    set(WS64 ON)
else()
    message(FATAL_ERROR "OE_WORD must be one of '32' or '64'.")
endif()

if(UNIX AND SGX)
    message(FATAL_ERROR "Intel SGX is not supported on Linux in this preview.")
endif()

# Assert that the respective TEE SDK's are present.
if(TZ AND ("$ENV{TA_DEV_KIT_DIR}" STREQUAL "") AND ("${TA_DEV_KIT_DIR}" STREQUAL ""))
    message(FATAL_ERROR "TA_DEV_KIT_DIR must be specified when building for ARM TrustZone.")
elseif(WIN32 AND SGX AND ("$ENV{SGXSDKInstallPath}" STREQUAL "") AND ("${SGXSDKInstallPath}" STREQUAL ""))
    message(FATAL_ERROR "The Intel SGX SDK is required when building for Intel SGX on Windows.")
endif()

# Propagate the environment variables into locals, if necessary.
if(TZ AND (NOT "$ENV{TA_DEV_KIT_DIR}" STREQUAL "") AND ("${TA_DEV_KIT_DIR}" STREQUAL ""))
    set(TA_DEV_KIT_DIR $ENV{TA_DEV_KIT_DIR})
elseif(WIN32 AND SGX AND (NOT "$ENV{SGXSDKInstallPath}" STREQUAL "") AND ("${SGXSDKInstallPath}" STREQUAL ""))
    set(SGXSDKInstallPath $ENV{SGXSDKInstallPath})
endif()

# Add common compiler definitions
if(SGX)
    add_definitions(-DOE_USE_SGX)
else()
    add_definitions(-DOE_USE_OPTEE)
    if(sim)
        add_definitions(-DOE_SIMULATE_OPTEE)
    endif()
endif()

# 3rd-party components
if(UNIX AND TZ)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../3rdparty/optee_client ${PROJECT_SOURCE_DIR}/../3rdparty/optee_client/out)
endif()

add_subdirectory(libsocket)

