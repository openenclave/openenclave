include(oeedl_file)

oeedl_file(../oeinternal.edl host GEN C_GEN H_GEN)
if(WIN32)
    sgxedl_file(../oeoverintelsgx.edl host GEN C_GEN H_GEN "${NP_PATH}/src;${SGXSDKInstallPath}/include")
endif()

# All combinations
set(SRCS oeshim_host.c uhelper_shared.c)
set(INCS
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
    PRIVATE ${NP_PATH}/include
    PRIVATE ${OE_PATH}/include)

# By TEE
if(TZ)
    list(APPEND SRCS ../optee_common.c)
elseif(SGX)
    list(APPEND SRCS ../sgx_common.c urpc_sgx.c)
endif()

# By OS, by TEE
if(UNIX)
    list(APPEND SRCS linux/stdext.c linux/uhelper.c)

    if(TZ)
        list(APPEND SRCS linux/teehost_optee.c linux/urpc_optee.c)
        list(APPEND INCS PRIVATE ${OPTEE_CLIENT_PATH}/public)
    endif()

elseif(WIN32)
    list(APPEND SRCS win32/uhelper.c)

    if(TZ)
        list(APPEND SRCS win32/teehost_optee.c urpc_optee.c)
    elseif(SGX)
        list(APPEND SRCS win32/teehost_sgx.c)
    endif()
endif()

add_library(oehost STATIC ${SRCS} ${GEN})

target_include_directories(oehost ${INCS})

if(UNIX)
    target_compile_definitions(oehost PRIVATE LINUX)
    target_include_directories(oehost PRIVATE ${NP_PATH}/include/linux)
elseif(WIN32)
    target_include_directories(oehost PRIVATE ${SGXSDKInstallPath}/include)
endif()
