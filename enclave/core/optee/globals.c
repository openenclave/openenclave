// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

#include <user_ta_header.h>

// These are defined in liboeutee.
extern uint8_t ta_heap[];
extern const size_t ta_heap_size;

/*
**==============================================================================
**
** Enclave boundaries:
**
**==============================================================================
*/

const void* __oe_get_enclave_base()
{
    return (void*)tainfo_get_rva();
}

const void* __oe_get_enclave_elf_header(void)
{
    return (const uint8_t*)__oe_get_enclave_base() + sizeof(struct ta_head);
}

/*
**==============================================================================
**
** Heap boundaries:
**
**==============================================================================
*/

const void* __oe_get_heap_base()
{
    return ta_heap;
}

size_t __oe_get_heap_size()
{
    return ta_heap_size;
}

const void* __oe_get_heap_end()
{
    return (const uint8_t*)__oe_get_heap_base() + __oe_get_heap_size();
}
