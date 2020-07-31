// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/internal/eeid.h>

/* This file avoids linking against the whole of eeid.c in
 * liboecore, while we need only one basic definition. */

int is_eeid_base_image(const volatile oe_enclave_size_settings_t* sizes)
{
    return sizes->num_heap_pages == 0 && sizes->num_stack_pages == 0 &&
           sizes->num_tcs == 0;
}