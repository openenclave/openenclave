// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/internal/eeid.h>
#include <openenclave/internal/raise.h>

#include <stdlib.h>

#include "test_helpers.h"

oe_result_t make_test_eeid(oe_eeid_t** eeid)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(oe_create_eeid_sgx(10, eeid));
    (*eeid)->version = 1;
    (*eeid)->data_size = 10;
    for (size_t i = 0; i < (*eeid)->data_size; i++)
        (*eeid)->data[i] = (uint8_t)i;
    (*eeid)->size_settings.num_heap_pages = 100;
    (*eeid)->size_settings.num_stack_pages = 50;
    (*eeid)->size_settings.num_tcs = 2;

    result = OE_OK;

done:
    return result;
}
