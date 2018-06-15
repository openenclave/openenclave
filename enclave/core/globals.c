// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

/* Note: The variables below are initialized during enclave loading */

/*
**==============================================================================
**
** Enclave boundaries:
**
**==============================================================================
*/

OE_EXPORT uint64_t __oe_num_pages;
OE_EXPORT uint64_t __oe_virtual_base_addr;

const void* __oe_get_enclave_base()
{
    /*
     * Note: The reference to &__oe_virtual_base_addr will be compiled
     * IP-relative by the C-compiler on x86_64, and hence does not have a
     * relocation entry. Thus it works both pre- and post-relocation.
     */
    return (uint8_t*)&__oe_virtual_base_addr - __oe_virtual_base_addr;
}

size_t __oe_get_enclave_size()
{
    return __oe_num_pages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** Reloc boundaries:
**
**==============================================================================
*/

OE_EXPORT uint64_t __oe_base_reloc_page;
OE_EXPORT uint64_t __oe_num_reloc_pages;

const void* __oe_get_reloc_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + (__oe_base_reloc_page * OE_PAGE_SIZE);
}

const void* __oe_get_reloc_end()
{
    return (const uint8_t*)__oe_get_reloc_base() + __oe_get_reloc_size();
}

const size_t __oe_get_reloc_size()
{
    return __oe_num_reloc_pages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** ECall boundaries:
**
**==============================================================================
*/

OE_EXPORT uint64_t __oe_base_ecall_page;
OE_EXPORT uint64_t __oe_num_ecall_pages;

const void* __oe_get_ecall_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + (__oe_base_ecall_page * OE_PAGE_SIZE);
}

const void* __oe_get_ecall_end()
{
    return (const uint8_t*)__oe_get_ecall_base() + __oe_get_ecall_size();
}

const size_t __oe_get_ecall_size()
{
    return __oe_num_ecall_pages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** Heap boundaries:
**
**==============================================================================
*/

OE_EXPORT uint64_t __oe_base_heap_page;
OE_EXPORT uint64_t __oe_num_heap_pages;

const void* __oe_get_heap_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + (__oe_base_heap_page * OE_PAGE_SIZE);
}

const size_t __oe_get_heap_size()
{
    return __oe_num_heap_pages * OE_PAGE_SIZE;
}

const void* __oe_get_heap_end()
{
    return (const uint8_t*)__oe_get_heap_base() + __oe_get_heap_size();
}
