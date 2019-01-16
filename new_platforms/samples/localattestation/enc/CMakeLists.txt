# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave)

oeedl_file(../localattestation.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(TARGET localattestation_enclave)

if(UNIX AND TZ)
    add_custom_target(${TARGET} ALL
        COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
            -f linux_gcc.mak
            OE_INC=${OE_PATH}/include
            NP_INC=${NP_PATH}/include
            TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
            CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
            O=${CMAKE_CURRENT_BINARY_DIR}
            AR_O=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
            GEN=${C_GEN}
        DEPENDS ${GEN})
    add_dependencies(${TARGET} oeenclave liboestdio_enc)
    add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E
            copy ${CMAKE_CURRENT_BINARY_DIR}/*.ta ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
elseif(WIN32 AND (SGX OR (TZ AND SIM)))
    if(TZ AND SIM)
        set(TARGET 97d140f4-5f59-4d1f-9735-cb21d49e7eb7)
    endif()

    add_enclave(
        TARGET ${TARGET}
        SOURCES enc.c ${GEN})
endif()
