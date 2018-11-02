// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

/* Note: The variables below are initialized during enclave loading */

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

/*
**==============================================================================
**
** Enclave boundaries:
**
**==============================================================================
*/

const void* __oe_get_enclave_base()
{
    /*
     * Note: The reference to &oe_enclave_properties_sgx will be compiled
     * IP-relative by the C-compiler on x86_64, and hence does not have a
     * relocation entry. Thus it works both pre- and post-relocation.
     */
    return (uint8_t*)&oe_enclave_properties_sgx -
           oe_enclave_properties_sgx.image_info.oeinfo_rva;
}

size_t __oe_get_enclave_size()
{
    return oe_enclave_properties_sgx.image_info.enclave_size;
}

/*
**==============================================================================
**
** Reloc boundaries:
**
**==============================================================================
*/

const void* __oe_get_reloc_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + oe_enclave_properties_sgx.image_info.reloc_rva;
}

const void* __oe_get_reloc_end()
{
    return (const uint8_t*)__oe_get_reloc_base() + __oe_get_reloc_size();
}

const size_t __oe_get_reloc_size()
{
    return oe_enclave_properties_sgx.image_info.reloc_size;
}

/*
**==============================================================================
**
** ECall boundaries:
**
**==============================================================================
*/

const void* __oe_get_ecall_base()
{
    const unsigned char* base = __oe_get_enclave_base();

    return base + oe_enclave_properties_sgx.image_info.ecall_rva;
}

const void* __oe_get_ecall_end()
{
    return (const uint8_t*)__oe_get_ecall_base() + __oe_get_ecall_size();
}

const size_t __oe_get_ecall_size()
{
    return oe_enclave_properties_sgx.image_info.ecall_size;
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
    const unsigned char* base = __oe_get_enclave_base();

    return base + oe_enclave_properties_sgx.image_info.heap_rva;
}

const size_t __oe_get_heap_size()
{
    return oe_enclave_properties_sgx.header.size_settings.num_heap_pages *
           OE_PAGE_SIZE;
}

const void* __oe_get_heap_end()
{
    return (const uint8_t*)__oe_get_heap_base() + __oe_get_heap_size();
}

/*
**==============================================================================
**
** oe_enclave:
**
**     The enclave handle obtained with oe_create_enclave() and passed
**     to the enclave during initialization (via OE_ECALL_INIT_ENCLAVE).
**
**==============================================================================
*/

oe_enclave_t* oe_enclave;

oe_enclave_t* oe_get_enclave(void)
{
    return oe_enclave;
}

/*
**==============================================================================
**
** Page-oriented convenience functions.
**
**==============================================================================
*/

uint64_t oe_get_base_heap_page(void)
{
    const uint64_t heap_base = (uint64_t)__oe_get_heap_base();
    const uint64_t enclave_base = (uint64_t)__oe_get_enclave_base();
    return (heap_base - enclave_base) / OE_PAGE_SIZE;
}

uint64_t oe_get_num_heap_pages(void)
{
    return __oe_get_heap_size() / OE_PAGE_SIZE;
}

uint64_t oe_get_num_pages(void)
{
    return __oe_get_enclave_size() / OE_PAGE_SIZE;
}
