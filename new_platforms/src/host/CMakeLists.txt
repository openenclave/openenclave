# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oehost)

oeedl_file(../oeinternal.edl host GEN C_GEN H_GEN)
if(WIN32 AND SGX)
    sgxedl_file(../oeoverintelsgx.edl host GEN C_GEN H_GEN "${NP_PATH}/src;${SGXSDKInstallPath}/include")
endif()

# All combinations
set(SRCS oeshim_host.c uhelper_shared.c)
set(INCS
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
    PUBLIC  ${NP_PATH}/include
    PUBLIC  ${OE_PATH}/include
    PRIVATE ${MBEDTLS_PATH}/include
    PRIVATE ${CYREP_PATH}/cyrep
    PRIVATE ${CYREP_PATH}/tcps
    PRIVATE ${TINYCBOR_PATH}/src)

set(CYREP_SRCS
    ${CYREP_PATH}/RiotAes128.c  ${CYREP_PATH}/RiotAesTables.c
    ${CYREP_PATH}/RiotBase64.c  ${CYREP_PATH}/RiotCrypt.c
    ${CYREP_PATH}/RiotDerEnc.c  ${CYREP_PATH}/RiotEcc.c
    ${CYREP_PATH}/RiotHmac.c    ${CYREP_PATH}/RiotKdf.c
    ${CYREP_PATH}/RiotSha256.c  ${CYREP_PATH}/RiotX509Bldr.c
    ${CYREP_PATH}/tcps/TcpsId.c ${CYREP_PATH}/tcps/cborhelper.c)

set(TINYCBOR_SRCS
    ${TINYCBOR_PATH}/src/cborencoder.c
    ${TINYCBOR_PATH}/src/cborparser.c)

list(APPEND SRCS ${CYREP_SRCS} ${TINYCBOR_SRCS})

# By TEE
if(TZ)
    list(APPEND SRCS ../optee_common.c)
elseif(SGX)
    list(APPEND SRCS ../sgx_common.c urpc_sgx.c)
endif()

# By OS, by TEE
if(UNIX)
    list(APPEND SRCS linux/stdext.c linux/uhelper.c)
	list(INSERT INCS 0 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/linux)
    list(APPEND INCS PUBLIC ${NP_PATH}/include/linux)

    if(TZ)
        list(APPEND SRCS linux/teehost_optee.c linux/urpc_optee.c)
        list(APPEND INCS PRIVATE ${OPTEE_CLIENT_PATH}/public)
    endif()
elseif(WIN32)
    list(APPEND SRCS win32/uhelper.c)
	list(INSERT INCS 0 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/win32)

    if(TZ)
        list(APPEND SRCS
            win32/teehost_optee.c
            win32/urpc_optee.c)

        if(NOT SIM)
            list(APPEND SRCS ${OPTEE_CALLS_PATH}/OpteeCalls/OpteeCalls.c)
        endif()

        list(APPEND INCS PRIVATE ${WDK_PATH})
        list(APPEND INCS PRIVATE ${OE_PATH}/3rdparty/OpteeCalls/OpteeCalls/inc)
        
        list(APPEND LIBS PUBLIC Rpcrt4)

        if(SIM)
            list(APPEND LIBS PUBLIC oehost_opteesim)
        endif()
    elseif(SGX)
        list(APPEND SRCS ../oeresult.c win32/teehost_sgx.c)
        list(APPEND INCS PUBLIC ${SGXSDKInstallPath}/include)
        
        set(SGX_PREFIX ${SGX_SDK_LIBRARIES_PREFIX}/$<IF:$<CONFIG:RelWithDebInfo>,Release,$<CONFIG>>)
        if(SIM)
            list(APPEND LIBS
                PUBLIC ${SGX_PREFIX}/sgx_urts_sim.lib
                PUBLIC ${SGX_PREFIX}/sgx_uae_service_sim.lib
                PUBLIC ${SGX_PREFIX}/sgx_uprotected_fs.lib)
        else()
            list(APPEND LIBS
                PUBLIC ${SGX_PREFIX}/sgx_urts.lib
                PUBLIC ${SGX_PREFIX}/sgx_uae_service.lib
                PUBLIC ${SGX_PREFIX}/sgx_uprotected_fs.lib)
        endif()
    endif()
endif()

add_library(${TARGET} STATIC ${SRCS} ${GEN})
target_include_directories(${TARGET} ${INCS})
target_link_libraries(${TARGET} ${LIBS})
