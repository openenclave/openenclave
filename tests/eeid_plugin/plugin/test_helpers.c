// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <stdlib.h>

#include "test_helpers.h"

oe_eeid_t* mk_test_eeid()
{
    oe_eeid_t* eeid = malloc(sizeof(oe_eeid_t) + sizeof(uint8_t) * 10);
    eeid->data_size = 10;
    for (size_t i = 0; i < eeid->data_size; i++)
        eeid->data[i] = (uint8_t)i;
    eeid->size_settings.num_heap_pages = 200;
    eeid->size_settings.num_stack_pages = 200;
    eeid->size_settings.num_tcs = 2;
    return eeid;
}
