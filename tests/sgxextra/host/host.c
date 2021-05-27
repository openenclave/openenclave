// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <malloc.h>
#include <openenclave/bits/sgx/sgxextra.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgxextra_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();
    int retval;
    const oe_enclave_setting_t* settings = NULL;
    uint32_t settings_count = 0;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <enclave>\n", argv[0]);
        return 1;
    }

    r = oe_create_sgxextra_enclave(
        argv[1], type, flags, settings, settings_count, &enclave);
    OE_TEST(r == OE_OK);

    r = sgxextra_ecall(enclave, &retval);
    OE_TEST(r == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (sgxextra)\n");

    return 0;
}

oe_result_t oe_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr)
{
    __attribute__((__aligned__(4096)))
    uint8_t page[OE_PAGE_SIZE];

    memset(page, 0xab, sizeof(page));

    if (baseaddr == 0)
    {
        /* called once for measurement */
        printf("oe_load_extra_enclave_data_hook(1)\n");
        fflush(stdout);
    }
    else
    {
        /* called a second time for running enclave */
        printf("oe_load_extra_enclave_data_hook(2)\n");
        fflush(stdout);
    }

    /* add a regular page before the heap */
    uint64_t flags = 0;
    flags |= SGX_SECINFO_REG;
    flags |= SGX_SECINFO_R;
    flags |= SGX_SECINFO_W;
    flags |= SGX_SECINFO_X;
    bool extend = true;
    assert(oe_load_extra_enclave_data(arg, 0, page, flags, extend) == OE_OK);

    return OE_OK;
}
