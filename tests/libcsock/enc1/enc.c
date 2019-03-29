// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/io.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/enclave.h>
#include "../client.h"
#include "../server.h"

void run_enclave_server(uint16_t port)
{
    oe_enable_feature(OE_FEATURE_HOST_FILES);
    oe_enable_feature(OE_FEATURE_HOST_SOCKETS);
    oe_enable_feature(OE_FEATURE_POLLING);

    oe_set_default_socket_devid(OE_DEVID_HOST_SOCKET);
    run_server(port);
}

void run_enclave_client(uint16_t port)
{
    oe_enable_feature(OE_FEATURE_HOST_FILES);
    oe_enable_feature(OE_FEATURE_HOST_SOCKETS);
    oe_enable_feature(OE_FEATURE_POLLING);

    oe_set_default_socket_devid(OE_DEVID_HOST_SOCKET);
    run_client(port);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
