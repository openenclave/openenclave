# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(aesm main.cpp)
target_link_libraries(aesm oehost)

# Additional compilation options when using libsgx instead of AESM
if(USE_LIBSGX)
target_compile_definitions(aesm PRIVATE OE_USE_LIBSGX)
endif()
target_compile_options(aesm PRIVATE -Wconversion -Wpointer-arith)
add_test(NAME tests/aesm COMMAND ./aesm)
set_tests_properties(tests/aesm PROPERTIES SKIP_RETURN_CODE 2)
