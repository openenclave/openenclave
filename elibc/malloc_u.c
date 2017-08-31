#include <stdlib.h>
#include <openenclave.h>
#include <oeinternal/calls.h>
#include "../enclave/td.h"

typedef unsigned long long WORD;

#define WORD_SIZE sizeof(WORD)

/*
**==============================================================================
**
** malloc_u()
**
**     Allocate N bytes from the host heap (via OCALL)
**
**==============================================================================
*/

void* malloc_u(size_t size)
{
    uint64_t argIn = size;
    uint64_t argOut = 0;

    if (__OE_OCall(OE_FUNC_MALLOC, argIn, &argOut) != OE_OK)
    {
        return NULL;
    }

    return (void*)argOut;
}

/*
**==============================================================================
**
** calloc_u()
**
**     Allocate N bytes from the host heap (via OCALL) and zero-fill
**
**==============================================================================
*/

void* calloc_u(size_t nmemb, size_t size)
{
    void* ptr = malloc_u(nmemb * size);

    if (ptr)
        memset(ptr, 0, nmemb * size);

    return ptr;
}

/*
**==============================================================================
**
** free_u()
**
**     Ask host to free memory allocated by malloc_u()
**
**==============================================================================
*/

void free_u(void* ptr)
{
    __OE_OCall(OE_FUNC_FREE, (uint64_t)ptr, NULL);
}

/*
**==============================================================================
**
** strdup_u()
**
**==============================================================================
*/

char* strdup_u(const char* str)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = strlen(str);

    if (!(p = malloc_u(len + 1)))
        return NULL;

    memcpy(p, str, len + 1);

    return p;
}

/*
**==============================================================================
**
** strdup_u()
**
**==============================================================================
*/

wchar_t* wcsdup_u(const wchar_t* wcs)
{
    wchar_t* p;
    size_t len;
    size_t size;

    if (!wcs)
        return NULL;

    len = wcslen(wcs);
    size = (len + 1) * sizeof(wchar_t);

    if (!(p = malloc_u(size)))
        return NULL;

    memcpy(p, wcs, size);

    return p;
}
