# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../poller.edl enclave gen)

add_enclave_executable(poller_enc
    enc.cpp ../client.cpp ../server.cpp ../poller.cpp poller_t.c)

maybe_build_using_clangw(poller_enc)

enclave_link_libraries(poller_enc oelibcxx oeenclave oehostepoll oehostsock)
