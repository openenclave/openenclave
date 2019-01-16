# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(add_enclave TARGET SOURCES)
    add_library(${TARGET} MODULE ${SOURCES})

    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET} oeenclave oestdio_enc oesocket_enc)

    if(NOT (TZ AND SIM))
        target_compile_options(${TARGET} PUBLIC "/X")
        target_compile_definitions(${TARGET} PUBLIC OE_NO_SAL)
    endif()

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG} PARENT_SCOPE)

    if(SGX)
        # NOTE: These three work for CMake 3.13+, but Azure DevOps currently has
        # 3.12 installed:
        #
        # target_link_options(${TARGET} BEFORE PRIVATE "/NODEFAULTLIB")
        # target_link_options(${TARGET} BEFORE PRIVATE "/NOENTRY")
        # target_link_options(${TARGET} BEFORE PRIVATE "/MANIFEST:NO")
        #
        # Workaround follows:
        set_target_properties(${TARGET} PROPERTIES LINK_FLAGS "/NODEFAULTLIB /NOENTRY /MANIFEST:NO")

        add_custom_command(TARGET ${TARGET} POST_BUILD
            COMMAND ${SGX_SDK_SIGN_TOOL} sign
                -key ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET}_private.pem
                -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET}.dll
                -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/$<CONFIG>/${TARGET}.signed.dll
                -config ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET}.config.xml)
    endif()
endfunction()
