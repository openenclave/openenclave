# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(TARGET oehost_opteesim)

add_library(${TARGET} STATIC uOptee.c)

target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/host/Simulator)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include)
target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)
target_include_directories(${TARGET} PRIVATE ${OPTEE_CALLS_PATH}/OpteeCalls/inc)
target_include_directories(${TARGET} PRIVATE ${WDK_PATH}/km)
