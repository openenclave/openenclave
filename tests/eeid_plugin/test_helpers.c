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
    oe_enclave_setting_eeid_t** eeid_setting,
    size_t data_size,
    bool static_sizes)
{
    oe_enclave_setting_eeid_t* setting =
        calloc(1, sizeof(oe_enclave_setting_eeid_t) + data_size);

    if (static_sizes)
    {
        /* Set EEID sizes to base-image sizes to indicate that we want to use
         * static sizes. */
        setting->size_settings.num_heap_pages = 0;
        setting->size_settings.num_stack_pages = 0;
        setting->size_settings.num_tcs = 1;
    }
    else
    {
        setting->size_settings.num_heap_pages = 100;
        setting->size_settings.num_stack_pages = 50;
        setting->size_settings.num_tcs = 2;
    }

    setting->data_size = data_size;
    for (size_t i = 0; i < data_size; i++)
        setting->data[i] = (uint8_t)i;

    *eeid_setting = setting;

    return OE_OK;
}
