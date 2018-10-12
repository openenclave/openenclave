# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
    # Produce single untrusted file
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/all_u.c

    # Run edger8r
    COMMAND 
        ${OE_BINDIR}/oeedger8r ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
            --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../edl
            --untrusted

    # Regenerate if any edl file changes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../edl/*.edl
)

add_executable(edl_host 
    main.cpp
    testarray.cpp
    testbasic.cpp
    testenum.cpp
    testforeign.cpp
    testmisc.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/all_u.c  
)

target_include_directories(edl_host PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_compile_options(edl_host PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_link_libraries(edl_host oehostapp)
