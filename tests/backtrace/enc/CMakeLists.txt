# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../backtrace.edl enclave gen)

add_enclave(TARGET backtrace_enc UUID c21d0c84-a32b-430a-ad9a-7bf8b47eff0c CXX SOURCES enc.cpp ${gen})

enclave_link_libraries(backtrace_enc oelibc)

enclave_include_directories(backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
