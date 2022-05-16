// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <malloc.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/host.h>
#include <openenclave/internal/sgx/extradata.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "extra_data_u.h"

#define SKIP_RETURN_CODE 2

static oe_result_t _load_extra_enclave_data_hook(
    oe_load_extra_enclave_data_hook_arg_t* arg,
    uint64_t baseaddr)
{
    uint64_t flags = 0;
    uint8_t* page;
    bool extend;

    page = (uint8_t*)oe_memalign(4096, OE_PAGE_SIZE);
    OE_TEST(page != NULL);

    memset(page, 0xab, OE_PAGE_SIZE);

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
    flags |= SGX_SECINFO_REG;
    flags |= SGX_SECINFO_R;
    flags |= SGX_SECINFO_W;
    flags |= SGX_SECINFO_X;
    extend = true;

    OE_TEST(oe_load_extra_enclave_data(arg, 0, page, flags, extend) == OE_OK);

    return OE_OK;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();
    int retval;
    const oe_enclave_setting_t* settings = NULL;
    uint32_t settings_count = 0;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <enclave> [zerobase|nozerobase]\n", argv[0]);
        return 1;
    }

    const bool enable_zerobase = strcmp(argv[2], "zerobase") == 0;

    if (enable_zerobase && !oe_sgx_is_flc_supported())
    {
        printf("=== tests skipped when FLC is not supported.\n");
        return SKIP_RETURN_CODE;
    }

    if (enable_zerobase && (flags & OE_ENCLAVE_FLAG_SIMULATE))
    {
        // zero-based enclaves are not supported in simulation mode
        printf("=== tests skipped in simulation mode.\n");
        return SKIP_RETURN_CODE;
    }

    oe_register_load_extra_enclave_data_hook(_load_extra_enclave_data_hook);

    r = oe_create_extra_data_enclave(
        argv[1], type, flags, settings, settings_count, &enclave);
    OE_TEST(r == OE_OK);

    r = extra_data_ecall(enclave, &retval);
    OE_TEST(r == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    if (enable_zerobase)
        printf("=== passed all tests (extra_data_with_zerobase)\n");
    else
        printf("=== passed all tests (extra_data)\n");

    return 0;
}
