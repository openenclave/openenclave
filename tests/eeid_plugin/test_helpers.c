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

oe_result_t make_test_eeid(
    oe_eeid_t** eeid,
    size_t data_size,
    uint8_t** data,
    size_t* out_size,
    bool static_sizes)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(oe_create_eeid_sgx(eeid));
    (*eeid)->version = 1;

    if (static_sizes)
    {
        /* Set EEID sizes to base-image sizes to indicate that we want to use
         * static sizes. */
        (*eeid)->size_settings.num_heap_pages = 0;
        (*eeid)->size_settings.num_stack_pages = 0;
        (*eeid)->size_settings.num_tcs = 1;
    }
    else
    {
        (*eeid)->size_settings.num_heap_pages = 100;
        (*eeid)->size_settings.num_stack_pages = 50;
        (*eeid)->size_settings.num_tcs = 2;
    }

    *out_size = data_size;
    *data = malloc(data_size);
    for (size_t i = 0; i < data_size; i++)
        (*data)[i] = (uint8_t)i;

    result = OE_OK;

done:
    return result;
}
