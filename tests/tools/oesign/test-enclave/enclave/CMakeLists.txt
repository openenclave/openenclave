# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../oesign_test.edl)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT oesign_test_t.h oesign_test_t.c oesign_test_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# Note that this test uses add_executable rather than add_enclave and its
# related macro definitions since add_enclave does enclave signing as part of
# the build, which is undesirable for the oesign tests.
#
# This may need to be revisited when other TEEs are supported by oesign, but it
# currently does not support OP-TEE, and the SGX LVI mitigations are irrelevant
# to the oesign test enclave.
add_executable(oesign_test_enc enc.c
                               ${CMAKE_CURRENT_BINARY_DIR}/oesign_test_t.c)

if (WIN32)
  maybe_build_using_clangw(oesign_test_enc)
endif ()

target_compile_definitions(oesign_test_enc PUBLIC OE_API_VERSION=2)

# Need for the generated file oesign_test_t.h
target_include_directories(oesign_test_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oesign_test_enc oeenclave oelibc)
