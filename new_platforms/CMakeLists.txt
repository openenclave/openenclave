cmake_minimum_required(VERSION 3.5.1 FATAL_ERROR)

project("Open Enclave SDK (New Platforms)" VERSION 0.1 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set(NP_OUTPUT_DIR ${PROJECT_BINARY_DIR}/output CACHE INTERNAL "")
set(NP_BINDIR ${NP_OUTPUT_DIR}/bin CACHE INTERNAL "")
set(NP_INCDIR ${NP_OUTPUT_DIR}/include CACHE INTERNAL "")
set(NP_LIBDIR ${NP_OUTPUT_DIR}/lib CACHE INTERNAL "")

option(USE_OPTEE "Build for OP-TEE" ON)
option(USE_SGX "Build for SGX" OFF)

option(USE_SIMULATION "Build for simulation" OFF)

if(USE_OPTEE AND USE_SGX)
    message(FATAL_ERROR "Choose either USE_OPTEE or USE_SGX, not both.")
endif()

if(UNIX AND USE_SGX)
    message(FATAL_ERROR "SGX not supported on Unix.")
endif()

if(USE_OPTEE)
    add_compile_definitions(OE_USE_OPTEE)
    if(USE_SIMULATION)
        add_compile_definitions(OE_SIMULATE_OPTEE)
    endif()
else()
    add_compile_definitions(OE_USE_SGX)
endif()

set(CMAKE_VERBOSE_MAKEFILE on)

add_subdirectory(${PROJECT_SOURCE_DIR}/../3rdparty/optee_client ${PROJECT_SOURCE_DIR}/../3rdparty/optee_client/out)

add_subdirectory(libsocket)
add_subdirectory(include)
