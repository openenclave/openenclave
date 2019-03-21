# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oeenclave)

oeedl_file(../oeinternal.edl enclave GEN C_GEN H_GEN)
if(WIN32 AND SGX)
    sgxedl_file(../oeoverintelsgx.edl enclave GEN C_GEN H_GEN "${NP_PATH}/src;${SGXSDKInstallPath}/include")
endif()

if(UNIX AND TZ)
    if(OE_USE_TA_DEV_KIT)
        add_custom_target(${TARGET} ALL
            COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/optee
                -f linux_gcc.mak
                OE_INC=${OE_PATH}/include
                NP_INC=${NP_PATH}/include
                OPTEE_OS_PATH=${OPTEE_OS_PATH}
                CYREP_PATH=${CYREP_PATH}
                MBEDTLS_PATH=${MBEDTLS_PATH}
                TINYCBOR_PATH=${TINYCBOR_PATH}
                TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR}
                CROSS_COMPILE=${OE_TA_TOOLCHAIN_PREFIX}
                O=${CMAKE_CURRENT_BINARY_DIR}
                LIB_O=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
                GEN=${C_GEN}
            DEPENDS ${GEN})
        add_dependencies(${TARGET} oeedger8rtool)
    else()
        add_enclave_library_ex(
            TARGET ${TARGET}
            SOURCES
                ${GEN}
                CallbackHelper.c cborhelper.c files_enc.c
                keygen.c oeshim_enc.c socket_enc.c string_t.c
                ../optee_common.c
                optee/ctype_optee.c optee/cyres_optee.c
                optee/except_optee.c optee/keygen_optee.c
                optee/oeresult_optee.c optee/rand_optee.c
                optee/report_optee.c optee/strings_optee.c
                optee/time_optee.c optee/trpc_optee.c
                ${CYREP_PATH}/RiotAes128.c ${CYREP_PATH}/RiotAesTables.c
                ${CYREP_PATH}/RiotBase64.c ${CYREP_PATH}/RiotCrypt.c
                ${CYREP_PATH}/RiotDerEnc.c ${CYREP_PATH}/RiotEcc.c
                ${CYREP_PATH}/RiotHmac.c   ${CYREP_PATH}/RiotKdf.c
                ${CYREP_PATH}/RiotSha256.c ${CYREP_PATH}/RiotX509Bldr.c
                ${CYREP_PATH}/tcps/TcpsId.c
                ${TINYCBOR_PATH}/src/cborencoder.c
                ${TINYCBOR_PATH}/src/cborparser.c)
        target_include_directories(${TARGET}
            PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
            PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
            PUBLIC ${NP_PATH}/include/optee/enclave
            PUBLIC ${NP_PATH}/include/optee
            PUBLIC ${NP_PATH}/include
            PUBLIC ${CYREP_PATH}/cyrep
            PUBLIC ${CYREP_PATH}/tcps
            PUBLIC ${TINYCBOR_PATH}/src
            PUBLIC ${MBEDTLS_PATH}/include
            PUBLIC ${OE_PATH}/include)
        file(GLOB RIOT_SRCS "${CYREP_PATH}/Riot*.c")
        set_source_files_properties(${RIOT_SRCS} PROPERTIES COMPILE_FLAGS -Wno-implicit-function-declaration)
    endif()
elseif(WIN32)
    # Source lists
    set(COMMON_SRCS
        CallbackHelper.c cborhelper.c files_enc.c
        keygen.c oeshim_enc.c socket_enc.c string_t.c)

    set(CYREP_SRCS
        ${CYREP_PATH}/RiotAes128.c ${CYREP_PATH}/RiotAesTables.c
        ${CYREP_PATH}/RiotBase64.c ${CYREP_PATH}/RiotCrypt.c
        ${CYREP_PATH}/RiotDerEnc.c ${CYREP_PATH}/RiotEcc.c
        ${CYREP_PATH}/RiotHmac.c   ${CYREP_PATH}/RiotKdf.c
        ${CYREP_PATH}/RiotSha256.c ${CYREP_PATH}/RiotX509Bldr.c
        ${CYREP_PATH}/tcps/TcpsId.c)

    # Include lists
    set(LOCAL_INCS
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    set(COMMON_INCS
        PUBLIC  ${NP_PATH}/include
        PUBLIC  ${OE_PATH}/include)

    set(EXTERNAL_INCS
        PUBLIC  ${TINYCBOR_PATH}/src
        PUBLIC  ${CYREP_PATH}/cyrep
        PUBLIC  ${CYREP_PATH}/tcps
        PUBLIC  ${MBEDTLS_PATH}/include)

    # Library lists
    if(TZ AND SIM)
        set(MBEDTLS_LIBS
            PUBLIC mbedtls
            PUBLIC mbedx509
            PUBLIC mbedcrypto)
    else()
        set(MBEDTLS_LIBS
            PUBLIC mbedtls_enc
            PUBLIC mbedx509_enc
            PUBLIC mbedcrypto_enc)
    endif()

    # By TEE ->
    if(SGX)
        # Source lists
        set(SGX_SRCS
            ../oeresult.c ../sgx_common.c
            sgx/except_sgx.c sgx/keygen_sgx.c
            sgx/log_sgx.c sgx/rand_sgx.c
            sgx/report_sgx.c sgx/strings_sgx.c
            sgx/time_sgx.c sgx/trpc_sgx.c
            #TODO: These two should be common but fail to compile under CMake.
            log_ocall_file.c logapp.c)

        # Include lists
        set(SGX_INCS
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sgx
            PUBLIC  ${SGXSDKInstallPath}/include
            PUBLIC  ${SGXSDKInstallPath}/include/tlibc
            PUBLIC  ${NP_PATH}/include/sgx/enclave)

        # Library lists
        set(SGX_PREFIX ${SGX_SDK_LIBRARIES_PREFIX}/$<IF:$<CONFIG:RelWithDebInfo>,Release,$<CONFIG>>)
        set(SGX_LIBS
            PUBLIC ${SGX_PREFIX}/sgx_tstdc.lib
            PUBLIC ${SGX_PREFIX}/sgx_tprotected_fs.lib
            PUBLIC ${SGX_PREFIX}/sgx_tcxx.lib
            PUBLIC ${SGX_PREFIX}/sgx_tcrypto.lib)

        # Some libraries change depending on whether this is a simulation
        # build.
        if(SIM)
            list(APPEND SGX_LIBS
                PUBLIC ${SGX_PREFIX}/sgx_trts_sim.lib
                PUBLIC ${SGX_PREFIX}/sgx_tservice_sim.lib)
        else()
            list(APPEND SGX_LIBS
                PUBLIC ${SGX_PREFIX}/sgx_trts.lib
                PUBLIC ${SGX_PREFIX}/sgx_tservice.lib)
        endif()

        # Compose the final source, include and libary lists.
        set(SRCS ${CYREP_SRCS} ${COMMON_SRCS} ${SGX_SRCS})
        set(INCS ${LOCAL_INCS} ${COMMON_INCS} ${EXTERNAL_INCS} ${SGX_INCS})
        set(LIBS ${SGX_LIBS} ${MBEDTLS_LIBS})
    elseif(TZ AND SIM)
        # Source lists
        set(TZ_SRCS
            ../optee_common.c
            optee/ctype_optee.c optee/cyres_optee.c
            optee/except_optee.c optee/keygen_optee.c
            optee/oeresult_optee.c optee/rand_optee.c
            optee/report_optee.c optee/strings_optee.c
            optee/time_optee.c optee/trpc_optee.c)

        # Include lists
        set(TZ_INCS
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/optee
            PUBLIC ${NP_PATH}/include/optee/enclave/Simulator
            PUBLIC ${NP_PATH}/include/optee/enclave
            PUBLIC ${NP_PATH}/include/optee)

        set(TZ_EXTERNAL_INCS
            PUBLIC ${OPTEE_OS_PATH}/lib/libutee/include
            PUBLIC ${OPTEE_OS_PATH}/lib/libutils/ext/include)

        # Library lists
        set(TZ_LIBS
            PUBLIC oeenclave_opteesim)

        # Compose the final source, include and libary lists.
        set(SRCS ${CYREP_SRCS} ${COMMON_SRCS} ${TZ_SRCS})
        set(INCS ${LOCAL_INCS} ${TZ_INCS} ${COMMON_INCS} ${TZ_EXTERNAL_INCS} ${EXTERNAL_INCS})
        set(LIBS ${TZ_LIBS} ${MBEDTLS_LIBS})
    endif()

    add_library(${TARGET} STATIC ${SRCS} ${GEN})

    target_include_directories(${TARGET} ${INCS})
    target_link_libraries(${TARGET} ${LIBS})

    if(SGX)
        target_compile_definitions(${TARGET} PRIVATE CONFIG_CYREP_SGX_BUILD)
    endif()

    target_compile_definitions(${TARGET} PRIVATE OPENSSL_NO_SOCK)

    if(NOT (TZ AND SIM))
        target_compile_options(${TARGET} PUBLIC "/X")
        target_compile_definitions(${TARGET} PUBLIC  OE_NO_SAL)
    endif()

    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_C_FLAGS       "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_CXX_FLAGS       "${CMAKE_CXX_FLAGS}")
    string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS       "${CMAKE_C_FLAGS}")
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    
    install(
        TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
