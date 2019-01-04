# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../oetests.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(TARGET_NAME oetests_enclave)

if(UNIX AND TZ)
    add_custom_target(${TARGET_NAME} ALL
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
    add_dependencies(${TARGET_NAME} oeenclave liboesocket_enc liboestdio_enc)
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E
            copy ${CMAKE_CURRENT_BINARY_DIR}/*.ta ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
elseif(WIN32 AND (SGX OR (TZ AND SIM)))
    if(TZ AND SIM)
        set(TARGET_NAME 3156152a-19d1-423c-96ea-5adf5675798f)
    endif()

    set(SRCS
        oetests_enclave.c
        OETestTA.c)

    add_library(${TARGET_NAME} MODULE ${SRCS} ${GEN})

    target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET_NAME} oeenclave oesocket_enc oestdio_enc)

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

    if(SGX)
        target_link_options(${TARGET_NAME} BEFORE PRIVATE "/NODEFAULTLIB")
        target_link_options(${TARGET_NAME} BEFORE PRIVATE "/NOENTRY")
        target_link_options(${TARGET_NAME} BEFORE PRIVATE "/MANIFEST:NO")

        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND ${SGX_SDK_SIGN_TOOL} sign
                -key ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}_private.pem
                -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET_NAME}.dll
                -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET_NAME}.signed.dll
                -config ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}.config.xml)
    endif()
endif()
