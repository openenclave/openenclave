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
elseif(WIN32)
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
        oeshim_enc.c
        socket_enc.c
        string_t.c)

    set(LOCAL_INCS
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    set(COMMON_INCS
        PUBLIC  ${NP_PATH}/include
        PUBLIC  ${OE_PATH}/include)

    set(EXTERNAL_INCS
        PRIVATE ${TINYCBOR_PATH}/src
        PRIVATE ${CYREP_PATH}/cyrep
        PRIVATE ${CYREP_PATH}/tcps)

    if(SGX)
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
            sgx/trpc_sgx.c
            #TODO: These two should be common but fail to compile under CMake.
            log_ocall_file.c
            logapp.c)

        set(SGX_INCS
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sgx
            PUBLIC  ${SGXSDKInstallPath}/include
            PUBLIC  ${SGXSDKInstallPath}/include/tlibc)

        set(SGX_LIBS_PREFIX ${SGX_SDK_LIBRARIES_PREFIX}/$<CONFIG>)
        set(SGX_LIBS
            PUBLIC ${SGX_LIBS_PREFIX}/sgx_tstdc.lib
            PUBLIC ${SGX_LIBS_PREFIX}/sgx_tprotected_fs.lib
            PUBLIC ${SGX_LIBS_PREFIX}/sgx_tcxx.lib
            PUBLIC ${SGX_LIBS_PREFIX}/sgx_tcrypto.lib)

        if(SIM)
            list(APPEND SGX_LIBS
                PUBLIC ${SGX_LIBS_PREFIX}/sgx_trts_sim.lib
                PUBLIC ${SGX_LIBS_PREFIX}/sgx_tservice_sim.lib)
        else()
            list(APPEND SGX_LIBS
                PUBLIC ${SGX_LIBS_PREFIX}/sgx_trts.lib
                PUBLIC ${SGX_LIBS_PREFIX}/sgx_tservice.lib)
        endif()

        set(SRCS ${CYREP_SRCS} ${COMMON_SRCS} ${SGX_SRCS})
        set(INCS ${LOCAL_INCS} ${COMMON_INCS} ${EXTERNAL_INCS} ${SGX_INCS})
        set(LIBS ${SGX_LIBS})
    elseif(TZ AND SIM)
        set(TZ_SRCS
            optee/ctype_optee.c
            optee/cyres_optee.c
            optee/except_optee.c
            optee/keygen_optee.c
            optee/oeresult_optee.c
            ../optee_common.c
            optee/rand_optee.c
            optee/report_optee.c
            optee/strings_optee.c
            optee/time_optee.c
            optee/trpc_optee.c)

        set(TZ_INCS
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/optee
            PUBLIC ${NP_PATH}/include/optee/enclave/Simulator
            PUBLIC ${NP_PATH}/include/optee/enclave
            PUBLIC ${NP_PATH}/include/optee)
        set(TZ_EXTERNAL_INCS
            PUBLIC ${OPTEE_OS_PATH}/lib/libutee/include
            PUBLIC ${OPTEE_OS_PATH}/lib/libutils/ext/include)

        set(SRCS ${CYREP_SRCS} ${COMMON_SRCS} ${TZ_SRCS})
        set(INCS ${LOCAL_INCS} ${TZ_INCS} ${COMMON_INCS} ${TZ_EXTERNAL_INCS} ${EXTERNAL_INCS})
        set(LIBS oeenclave_opteesim)
    endif() 

    add_library(oeenclave STATIC ${SRCS} ${GEN})

    target_include_directories(oeenclave ${INCS})

    if(SGX)
        target_compile_definitions(oeenclave PRIVATE CONFIG_CYREP_SGX_BUILD)
    endif()
    target_compile_definitions(oeenclave PRIVATE OPENSSL_NO_SOCK)

    target_link_libraries(oeenclave ${LIBS})

    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()
