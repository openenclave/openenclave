// Copyright (c) Open Enclave SDK contributors.
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

const void* __oe_get_enclave_start_address()
{
    return (void*)tainfo_get_rva();
}

const void* __oe_get_enclave_base_address()
{
    return __oe_get_enclave_start_address();
}

uint8_t __oe_get_enclave_create_zero_base_flag()
{
    return 0;
}

uint64_t __oe_get_configured_enclave_start_address()
{
    return 0;
}

const void* __oe_get_enclave_elf_header(void)
{
    return (const uint8_t*)__oe_get_enclave_start_address() +
           sizeof(struct ta_head);
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

/*
**==============================================================================
**
** Information for the module.
**
**==============================================================================
*/

/* Module loading is currently not supported in the OP-TEE. */
const oe_enclave_module_info_t* oe_get_module_info(void)
{
    return NULL;
}
