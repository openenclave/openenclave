# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(cppException_enc
  enc.cpp
  cppException.cpp)

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)

if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # Note that this file explicitly tests "bad" code which throws an
  # exception despite `noexcept`, hence the disabled warning here.
  target_compile_options(cppException_enc PRIVATE -Wno-exceptions)
endif ()

target_link_libraries(cppException_enc oelibcxx oeenclave)
