# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(tlssrv tlssrv.c srv.c)

target_include_directories(tlssrv PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(tlssrv
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

add_test(NAME tlssrv COMMAND tlssrv)
