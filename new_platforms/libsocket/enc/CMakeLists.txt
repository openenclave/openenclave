# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oesocket_enc)

oeedl_file(${OE_PATH}/include/openenclave/socket.edl enclave GEN C_GEN H_GEN)

if(UNIX AND TZ)
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
        "lib${TARGET}.a;socket_insecure_enc.o")

    add_custom_target(lib${TARGET} ALL
        COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
            -f linux_gcc.mak
            OE_INC=${OE_PATH}/include
            NP_INC=${NP_PATH}/include
            TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
            CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
            O=${CMAKE_CURRENT_BINARY_DIR}
            LIB_O=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
            GEN=${C_GEN}
        DEPENDS ${GEN}
        SOURCES socket_insecure_enc.c)
elseif(WIN32)
    set(SRCS socket_insecure_enc.c)

    add_library(${TARGET} ${SRCS} ${GEN})

    if(SGX)
        target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include)
        target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include/tlibc)
    elseif(TZ AND SIM)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave/Simulator)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee)
        target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
        target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)
    endif()

    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
    target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include)

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()
