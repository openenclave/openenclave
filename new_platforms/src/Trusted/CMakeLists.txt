# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

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
            LIB_O=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
            GEN=${C_GEN}
        DEPENDS ${GEN})
elseif(WIN32 AND SGX)
    set(CYREP_SRCS
        ${CYREP_PATH}/RiotAes128.c
        ${CYREP_PATH}/RiotAesTables.c
        ${CYREP_PATH}/RiotBase64.c
        ${CYREP_PATH}/RiotCrypt.c
        ${CYREP_PATH}/RiotDerEnc.c
        ${CYREP_PATH}/RiotEcc.c
        ${CYREP_PATH}/RiotHmac.c
        ${CYREP_PATH}/RiotKdf.c
        ${CYREP_PATH}/RiotSha256.c
        ${CYREP_PATH}/RiotX509Bldr.c)

    set(COMMON_SRCS
        CallbackHelper.c
        cborhelper.c
        files_enc.c
        keygen.c
        log_ocall_file.c
        logapp.c
        oeshim_enc.c
        socket_enc.c
        string_t.c)

    set(SGX_SRCS
        ../oeresult.c
        ../sgx_common.c
        sgx/except_sgx.c
        sgx/keygen_sgx.c
        sgx/log_sgx.c
        sgx/rand_sgx.c
        sgx/report_sgx.c
        sgx/strings_sgx.c
        sgx/time_sgx.c
        sgx/trpc_sgx.c)

    set(SRCS ${CYREP_SRCS} ${COMMON_SRCS} ${SGX_SRCS} ${GEN})

    set(INCS
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sgx
        PUBLIC  ${NP_PATH}/include
        PUBLIC  ${OE_PATH}/include
        PUBLIC  ${SGXSDKInstallPath}/include
        PUBLIC  ${SGXSDKInstallPath}/include/tlibc
        PRIVATE ${TINYCBOR_PATH}/src
        PRIVATE ${CYREP_PATH}/cyrep
        PRIVATE ${CYREP_PATH}/tcps)

    set(PREFIX ${SGX_SDK_LIBRARIES_PREFIX}/$<CONFIG>)
    if(SIM)
        set(LIBS
                PUBLIC ${PREFIX}/sgx_tstdc.lib
                PUBLIC ${PREFIX}/sgx_tprotected_fs.lib
                PUBLIC ${PREFIX}/sgx_tcxx.lib
                PUBLIC ${PREFIX}/sgx_trts_sim.lib
                PUBLIC ${PREFIX}/sgx_tservice_sim.lib
                PUBLIC ${PREFIX}/sgx_tcrypto.lib)
    else()
        set(LIBS
                PUBLIC ${PREFIX}/sgx_tstdc.lib
                PUBLIC ${PREFIX}/sgx_tprotected_fs.lib
                PUBLIC ${PREFIX}/sgx_tcxx.lib
                PUBLIC ${PREFIX}/sgx_trts.lib
                PUBLIC ${PREFIX}/sgx_tservice.lib
                PUBLIC ${PREFIX}/sgx_tcrypto.lib)
    endif()

    add_library(oeenclave STATIC ${SRCS} ${GEN})

    target_include_directories(oeenclave ${INCS})

    target_compile_definitions(oeenclave PRIVATE CONFIG_CYREP_SGX_BUILD)
    target_compile_definitions(oeenclave PRIVATE OPENSSL_NO_SOCK)
    target_link_libraries(oeenclave ${LIBS})

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()
