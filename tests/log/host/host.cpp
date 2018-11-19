// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/oelog-host.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

const char* arg0;

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    r = oe_create_enclave(argv[1], type, flags, NULL, 0, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    const char* logfile = "log.tmp";
    OE_TEST(oe_log_init(OE_LOG_INFO, logfile) == 0);
    OE_TEST(oe_log_enclave_init(enclave, OE_LOG_INFO) == 0);

    /* Test() */
    {
        r = oe_call_enclave(enclave, "Test", NULL);
        OE_TEST(r == OE_OK);
    }

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
