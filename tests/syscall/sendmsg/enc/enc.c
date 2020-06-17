// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/tests.h>
#include "../client.h"
#include "../server.h"

static void _init(void)
{
    static bool _initialized = false;

    if (!_initialized)
    {
        OE_TEST(oe_load_module_host_socket_interface() == OE_OK);

        _initialized = true;
    }
}

void run_enclave_server(uint16_t port)
{
    _init();
    run_server(port);
}

void run_enclave_client(uint16_t port)
{
    _init();
    run_client(port);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
