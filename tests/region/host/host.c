// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <malloc.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/host.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "region_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();
    int retval;
    const oe_enclave_setting_t* settings = NULL;
    uint32_t settings_count = 0;
#ifdef OE_WITH_EXPERIMENTAL_EEID
    oe_enclave_setting_t setting_buf;
    oe_eeid_t* eeid = NULL;
#endif

#ifdef OE_WITH_EXPERIMENTAL_EEID
    {
        char data[] = "abcdefghijklmnopqrstuvwxyz";

        oe_create_eeid_sgx(sizeof(data), &eeid);
        eeid->size_settings.num_heap_pages = 4096;
        eeid->size_settings.num_stack_pages = 1024;
        eeid->size_settings.num_tcs = 4;
        memcpy(eeid->data, data, sizeof(data));

        memset(&setting_buf, 0, sizeof(setting_buf));
        setting_buf.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
        setting_buf.u.eeid = eeid;
        settings = &setting_buf;
        settings_count = 1;
    }
#endif

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <enclave>\n", argv[0]);
        return 1;
    }

    r = oe_create_region_enclave(
        argv[1], type, flags, settings, settings_count, &enclave);
    OE_TEST(r == OE_OK);

    r = region_ecall(enclave, &retval);
    OE_TEST(r == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (region)\n");

#ifdef OE_WITH_EXPERIMENTAL_EEID
    free(eeid);
#endif

    return 0;
}

oe_result_t oe_region_add_regions(oe_region_context_t* context)
{
    uint64_t vaddr = context->vaddr;
    uint64_t flags = SGX_SECINFO_R | SGX_SECINFO_REG;
    uint8_t* page = NULL;

    if (!(page = memalign(OE_PAGE_SIZE, OE_PAGE_SIZE)))
        assert(0);

    memset(page, 0xAA, OE_PAGE_SIZE);

    assert(oe_region_start(context, 1001, false) == OE_OK);
    assert(oe_region_add_page(context, vaddr, page, flags, true) == OE_OK);
    assert(oe_region_end(context) == OE_OK);

    free(page);

    return OE_OK;
}
