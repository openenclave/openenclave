# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oestdio_enc)

oeedl_file(${OE_PATH}/include/openenclave/stdio.edl enclave GEN C_GEN H_GEN)

if(UNIX AND TZ)
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
        "lib${TARGET}.a;stdio_enc.o;optee/files_optee.o")

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
        SOURCES stdio_enc.c optee/files_optee.c)

        add_dependencies(lib${TARGET} oeedger8rtool)
elseif(WIN32)
    set(SRCS stdio_enc.c)

    if(SGX)
        list(APPEND SRCS sgx/files_sgx.c)
    elseif(TZ AND SIM)
        list(APPEND SRCS optee/files_optee.c)
    endif()

    add_library(${TARGET} ${SRCS} ${GEN})

    if(SGX)
        target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include)
        target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include/tlibc)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/sgx/enclave)
    elseif(TZ AND SIM)
        target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave/Simulator)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee/enclave)
        target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/optee)
        target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
        target_include_directories(${TARGET} PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)
        target_include_directories(${TARGET} PRIVATE ${MBEDTLS_PATH}/include)
    endif()

    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
    target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include)

    if(NOT (TZ AND SIM))
        target_compile_options(${TARGET} PUBLIC "/X")
        target_compile_definitions(${TARGET} PUBLIC OE_NO_SAL)
    endif()

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

    install(
        TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
