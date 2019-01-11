# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(sgx_enclave)

oeedl_file(../sockets.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(TARGET sockets_enclave)

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
    add_dependencies(${TARGET} oeenclave liboestdio_enc liboesocket_enc)
    add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E
            copy ${CMAKE_CURRENT_BINARY_DIR}/*.ta ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
elseif(WIN32 AND (SGX OR (TZ AND SIM)))
    if(TZ AND SIM)
        set(TARGET aac3129e-c244-4e09-9e61-d4efcf31bca3)
    endif()

    set(SRCS sockets.c)

    add_library(${TARGET} MODULE ${SRCS} ${GEN})

    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET} oeenclave oestdio_enc oesocket_enc)

    if(NOT (TZ AND SIM))
        target_compile_options(${TARGET} PUBLIC "/X")
        target_compile_definitions(${TARGET} PUBLIC OE_NO_SAL)
    endif()

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

    if(SGX)
        sgx_enclave_configure_target(${TARGET})
    endif()
endif()
