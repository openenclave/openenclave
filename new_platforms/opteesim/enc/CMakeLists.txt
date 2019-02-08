# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(TARGET oeenclave_opteesim)

add_library(${TARGET} STATIC
    ${CYREP_PATH}/tcps/TcpsId.c
    ${TINYCBOR_PATH}/src/cborencoder.c
    ${TINYCBOR_PATH}/src/cborparser.c
    cyres_sim.c
    memory-sim.c
    stdio-sim.c
    string-sim.c
    tcrypto-sim.c
    tobject-sim.c
    trpc_sim.c
    ttime-sim.c)

target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave/Simulator)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee)
target_include_directories(${TARGET} PRIVATE ${CYREP_PATH}/cyrep)
target_include_directories(${TARGET} PRIVATE ${CYREP_PATH}/tcps)
target_include_directories(${TARGET} PRIVATE ${TINYCBOR_PATH}/src)
target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)

install(
    TARGETS ${TARGET}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
