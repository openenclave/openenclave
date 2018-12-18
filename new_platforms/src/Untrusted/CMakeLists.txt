# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

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
    PUBLIC ${NP_PATH}/include
    PUBLIC ${OE_PATH}/include)

# By TEE
if(TZ)
    list(APPEND SRCS ../optee_common.c)
elseif(SGX)
    list(APPEND SRCS ../sgx_common.c urpc_sgx.c)
endif()

# By OS, by TEE
if(UNIX)
    list(APPEND SRCS linux/stdext.c linux/uhelper.c)
    list(APPEND INCS PUBLIC ${NP_PATH}/include/linux)

    if(TZ)
        list(APPEND SRCS linux/teehost_optee.c linux/urpc_optee.c)
        list(APPEND INCS PRIVATE ${OPTEE_CLIENT_PATH}/public)
    endif()
elseif(WIN32)
    list(APPEND SRCS win32/uhelper.c)

    if(TZ)
        list(APPEND SRCS
            win32/teehost_optee.c
            win32/urpc_optee.c
            ${OPTEE_CALLS_PATH}/OpteeCalls/OpteeCalls.c)

        list(APPEND INCS PRIVATE ${WDK_PATH}/km)
        list(APPEND INCS PRIVATE ${OE_PATH}/3rdparty/OpteeCalls/OpteeCalls/inc)
        
        set(LIBS PUBLIC Rpcrt4)
    elseif(SGX)
        list(APPEND SRCS ../oeresult.c win32/teehost_sgx.c)
        list(APPEND INCS PUBLIC ${SGXSDKInstallPath}/include)
        
        set(PREFIX ${SGX_SDK_LIBRARIES_PREFIX}/$<CONFIG>)
        if(SIM)
            set(LIBS
                PUBLIC ${PREFIX}/sgx_urts_sim.lib
                PUBLIC ${PREFIX}/sgx_uae_service_sim.lib
                PUBLIC ${PREFIX}/sgx_uprotected_fs.lib)
        else()
            set(LIBS
                PUBLIC ${PREFIX}/sgx_urts.lib
                PUBLIC ${PREFIX}/sgx_uae_service.lib
                PUBLIC ${PREFIX}/sgx_uprotected_fs.lib)
        endif()
    endif()
endif()

add_library(oehost STATIC ${SRCS} ${GEN})

target_include_directories(oehost ${INCS})

if(UNIX)
    target_compile_definitions(oehost PRIVATE LINUX)
elseif(WIN32)
    target_link_libraries(oehost ${LIBS})
endif()
