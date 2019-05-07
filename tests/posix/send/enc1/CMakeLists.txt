# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../libcsock.edl enclave gen)

add_executable(libcsock_enc1 enc.c ../client.c ../server.c ${gen})
maybe_build_using_clangw(libcsock_enc1)

target_link_libraries(libcsock_enc1 oelibc oeenclave oehostsock)
