// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/oelog.h>
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

    // set OE_LOG_PATH
    OE_TEST(setenv("OE_LOG_PATH", "log.tmp", 1) == 0);
    // set OE_LOG_LEVEL
    OE_TEST(setenv("OE_LOG_LEVEL", "info", 1) == 0);
    // set OE_LOG_FLAGS
    uint64_t log_flags = OE_LOG_FLAGS_ATTESTATION | OE_LOG_FLAGS_COMMON;
    char flags_str[20];
    sprintf(flags_str, "0x%lx", log_flags);
    setenv("OE_LOG_FLAGS", flags_str, 1);

    OE_TEST(oe_log_host_init() == 0);
    OE_TEST(oe_log_enclave_init(enclave) == OE_OK);

    oe_log(OE_LOG_FLAGS_COMMON, OE_LOG_INFO, "Starting the log %s", "now");
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
