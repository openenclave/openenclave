oeedl_file(../oetests.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(TARGET_NAME oetests_enclave)

set(SRCS
    ${TARGET_NAME}.c
    OETestTA.c)

if(WIN32 AND SGX)
    add_library(${TARGET_NAME} MODULE ${SRCS} ${GEN})

    target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET_NAME} oeenclave oesocket_enc oestdio_enc)

    target_link_options(${TARGET_NAME} BEFORE PRIVATE "/NODEFAULTLIB")
    target_link_options(${TARGET_NAME} BEFORE PRIVATE "/NOENTRY")
    target_link_options(${TARGET_NAME} BEFORE PRIVATE "/MANIFEST:NO")

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${SGX_SDK_SIGN_TOOL} sign
            -key ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}_private.pem
            -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET_NAME}.dll
            -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET_NAME}.signed.dll
            -config ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}.config.xml)
endif()
