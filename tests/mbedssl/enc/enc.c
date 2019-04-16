// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

extern bool oe_disable_debug_malloc_check;

void initialize_enclave(void)
{
    oe_disable_debug_malloc_check = true;

    OE_TEST(oe_load_module_hostfs() == OE_OK);
    OE_TEST(oe_load_module_hostsock() == OE_OK);
    OE_TEST(oe_load_module_hostresolver() == OE_OK);
    OE_TEST(oe_load_module_polling() == OE_OK);
    OE_TEST(oe_load_module_eventfd() == OE_OK);

    if (mount("/", "/", "hostfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }
}

void shutdown_enclave(void)
{
    if (umount("/") != 0)
    {
        fprintf(stderr, "umount() failed\n");
        exit(1);
    }
}

void run_client(void)
{
    extern int client_main(int argc, const char* argv[]);
    int ret;

    const char* argv[] = {
        "/tmp/client",
        NULL,
    };

    ret = client_main(1, argv);

    if (ret != 0)
        OE_TEST("client_main() failed" == NULL);
}

void run_server(void)
{
    extern int server_main(int argc, const char* argv[]);

    const char* argv[] = {
        "/tmp/server",
        NULL,
    };

    if (server_main(1, argv) != 0)
    {
        assert("server_main() failed" == NULL);
        exit(1);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
