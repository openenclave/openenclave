# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../cppException.edl enclave gen)

add_executable(cppException_enc enc.cpp cppException.cpp ${gen})

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)

if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # Note that this file explicitly tests "bad" code which throws an
  # exception despite `noexcept`, hence the disabled warning here.
  target_compile_options(cppException_enc PRIVATE -Wno-exceptions)
endif ()

target_include_directories(cppException_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cppException_enc oelibcxx oeenclave)
