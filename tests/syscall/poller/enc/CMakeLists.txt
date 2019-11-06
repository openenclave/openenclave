# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../poller.edl enclave gen)

add_executable(poller_enc
    enc.cpp ../client.cpp ../server.cpp ../poller.cpp ${gen})

maybe_build_using_clangw(poller_enc)

target_link_libraries(poller_enc oelibcxx oeenclave oehostepoll oehostsock)
