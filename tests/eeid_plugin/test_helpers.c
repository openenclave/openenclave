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

oe_result_t make_test_eeid(oe_eeid_t** eeid, size_t data_size)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(oe_create_eeid_sgx(data_size, eeid));
    (*eeid)->version = 1;
    (*eeid)->data_size = data_size;
    for (size_t i = 0; i < data_size; i++)
        (*eeid)->data[i] = 'a' + (i % 26);
    (*eeid)->data[data_size - 1] = 0;
    (*eeid)->size_settings.num_heap_pages = 110 + (data_size / OE_PAGE_SIZE);
    (*eeid)->size_settings.num_stack_pages = 50;
    (*eeid)->size_settings.num_tcs = 2;

    result = OE_OK;

done:
    return result;
}
