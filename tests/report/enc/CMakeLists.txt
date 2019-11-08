# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../tests.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET report_enc UUID 20b1a091-50da-4e57-b58c-0a8489cb64a6
  SOURCES enc.cpp datetime.cpp ../common/tests.cpp ${gen})

target_include_directories(report_enc PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common)

target_link_libraries(report_enc oelibc)
