// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

/* Note: The variables below are initialized during enclave loading */

/*
**==============================================================================
**
** Enclave boundaries:
**
**==============================================================================
*/

OE_EXPORT unsigned long long __oe_numPages;
OE_EXPORT unsigned long long __oe_virtualBaseAddr;

const void* __OE_GetEnclaveBase()
{
    return (uint8_t*)&__oe_virtualBaseAddr - __oe_virtualBaseAddr;
}

size_t __OE_GetEnclaveSize()
{
    return __oe_numPages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** Reloc boundaries:
**
**==============================================================================
*/

OE_EXPORT unsigned long long __oe_baseRelocPage;
OE_EXPORT unsigned long long __oe_numRelocPages;

const void* __OE_GetRelocBase()
{
    const unsigned char* base = __OE_GetEnclaveBase();

    return base + (__oe_baseRelocPage * OE_PAGE_SIZE);
}

const void* __OE_GetRelocEnd()
{
    return (const uint8_t*)__OE_GetRelocBase() + __OE_GetRelocSize();
}

const size_t __OE_GetRelocSize()
{
    return __oe_numRelocPages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** ECall boundaries:
**
**==============================================================================
*/

OE_EXPORT unsigned long long __oe_baseECallPage;
OE_EXPORT unsigned long long __oe_numECallPages;

const void* __OE_GetECallBase()
{
    const unsigned char* base = __OE_GetEnclaveBase();

    return base + (__oe_baseECallPage * OE_PAGE_SIZE);
}

const void* __OE_GetECallEnd()
{
    return (const uint8_t*)__OE_GetECallBase() + __OE_GetECallSize();
}

const size_t __OE_GetECallSize()
{
    return __oe_numECallPages * OE_PAGE_SIZE;
}

/*
**==============================================================================
**
** Heap boundaries:
**
**==============================================================================
*/

OE_EXPORT unsigned long long __oe_baseHeapPage;
OE_EXPORT unsigned long long __oe_numHeapPages;

const void* __OE_GetHeapBase()
{
    const unsigned char* base = __OE_GetEnclaveBase();

    return base + (__oe_baseHeapPage * OE_PAGE_SIZE);
}

const size_t __OE_GetHeapSize()
{
    return __oe_numHeapPages * OE_PAGE_SIZE;
}

const void* __OE_GetHeapEnd()
{
    return (const uint8_t*)__OE_GetHeapBase() + __OE_GetHeapSize();
}
