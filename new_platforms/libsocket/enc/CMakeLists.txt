include(oeedl_file)

oeedl_file(../../../include/openenclave/socket.edl enclave GEN C_GEN H_GEN)

if(UNIX)
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
        "liboesocket_enc.a;../socket_insecure_enc.o")

    add_custom_target(liboesocket_enc ALL
        COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
            -f linux_gcc.mak
            OE_INC=${PROJECT_SOURCE_DIR}/../include
            NP_INC=${PROJECT_SOURCE_DIR}/include
            TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
            CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
            O=${CMAKE_CURRENT_BINARY_DIR}
            GEN=${C_GEN}
        DEPENDS ${GEN}
        SOURCES socket_insecure_enc.c)
endif()
