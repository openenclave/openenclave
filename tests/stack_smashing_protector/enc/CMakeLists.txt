# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(OUTPUT ssp_t.h ssp_t.c ssp_args.h
  DEPENDS ../ssp.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../ssp.edl)

add_enclave(TARGET ssp_enc SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/ssp_t.c)

# The flag -fstack-protector-all can make sure stack protector is turned on.
set_source_files_properties(enc.cpp PROPERTIES COMPILE_FLAGS -fstack-protector-all)

# Need for the generated file ssp_t.h
enclave_include_directories(ssp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(ssp_enc oelibcxx)
