include(oeedl_file)

oeedl_file(../oeinternal.edl enclave GEN C_GEN H_GEN)
if(WIN32 AND SGX)
    sgxedl_file(../oeoverintelsgx.edl enclave GEN C_GEN H_GEN "${NP_PATH}/src;${SGXSDKInstallPath}/include")
endif()

if(UNIX AND TZ)
    add_custom_target(oeenclave ALL
        COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
            -f linux_gcc.mak
            OE_INC=${OE_PATH}/include
            NP_INC=${NP_PATH}/include
            OPTEE_OS_PATH=${OPTEE_OS_PATH}
            RIOT_PATH=${RIOT_PATH}
            TINYCBOR_PATH=${TINYCBOR_PATH}
            TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
            CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
            O=${CMAKE_CURRENT_BINARY_DIR}
            GEN=${C_GEN}
        DEPENDS ${GEN})
elseif(WIN32 AND SGX)
endif()
