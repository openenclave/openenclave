#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include "td.h"

typedef unsigned long long WORD;

#define WORD_SIZE sizeof(WORD)

/*
**==============================================================================
**
** OE_HostMalloc()
**
**     Allocate N bytes from the host heap (via OCALL)
**
**==============================================================================
*/

void* OE_HostMalloc(oe_size_t size)
{
    oe_uint64_t argIn = size;
    oe_uint64_t argOut = 0;

    if (__OE_OCall(OE_FUNC_MALLOC, argIn, &argOut) != OE_OK)
    {
        return OE_NULL;
    }

    return (void*)argOut;
}

/*
**==============================================================================
**
** OE_HostCalloc()
**
**     Allocate N bytes from the host heap (via OCALL) and zero-fill
**
**==============================================================================
*/

void* OE_HostCalloc(oe_size_t nmemb, oe_size_t size)
{
    void* ptr = OE_HostMalloc(nmemb * size);

    if (ptr)
        OE_Memset(ptr, 0, nmemb * size);

    return ptr;
}

/*
**==============================================================================
**
** OS_HostFree()
**
**     Ask host to OE_Free memory allocated by OE_HostMalloc()
**
**==============================================================================
*/

void OE_HostFree(void* ptr)
{
    __OE_OCall(OE_FUNC_FREE, (oe_uint64_t)ptr, OE_NULL);
}

/*
**==============================================================================
**
** OE_HostStrdup()
**
**==============================================================================
*/

char* OE_HostStrdup(const char* str)
{
    char* p;
    oe_size_t len;

    if (!str)
        return OE_NULL;

    len = OE_Strlen(str);

    if (!(p = OE_HostMalloc(len + 1)))
        return OE_NULL;

    OE_Memcpy(p, str, len + 1);

    return p;
}
