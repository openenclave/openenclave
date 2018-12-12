include(oeedl_file)

oeedl_file(${OE_PATH}/include/openenclave/stdio.edl enclave GEN C_GEN H_GEN)

if(UNIX AND TZ)
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
        "liboestdio_enc.a;stdio_enc.o;optee/files_optee.o")

    add_custom_target(liboestdio_enc ALL
        COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
            -f linux_gcc.mak
            OE_INC=${OE_PATH}/include
            NP_INC=${NP_PATH}/include
            TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
            CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
            O=${CMAKE_CURRENT_BINARY_DIR}
            GEN=${C_GEN}
        DEPENDS ${GEN}
        SOURCES stdio_enc.c optee/files_optee.c)
elseif(WIN32 AND SGX)
    set(SRCS stdio_enc.c sgx/files_sgx.c)

    add_library(oestdio_enc ${SRCS} ${GEN})

    target_compile_definitions(oestdio_enc PRIVATE OE_USE_SGX)

    target_include_directories(oestdio_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_include_directories(oestdio_enc PRIVATE ${OE_PATH}/include)
    target_include_directories(oestdio_enc PRIVATE ${NP_PATH}/include)
    target_include_directories(oestdio_enc PRIVATE ${SGXSDKInstallPath}/include)
    target_include_directories(oestdio_enc PRIVATE ${SGXSDKInstallPath}/include/tlibc)
endif()
