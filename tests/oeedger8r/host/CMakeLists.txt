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

    # Regenerate if any edl file changes or oeedger8r changes
    # Temorary workaround:
    # Add explict dependency to oeedger8r binary.
    # oeedger8r custom target cannot declare its output binary.
    # Without the explicity dependecy to the binary below, running make on a test
    # will rebuild the edger8r if it is out of date, but will not invoke the newly build edger8r
    # on the edl file.    
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../edl/*.edl oeedger8r ${OE_BINDIR}/oeedger8r
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
