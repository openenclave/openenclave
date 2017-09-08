#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include "td.h"

typedef unsigned long long WORD;

#define WORD_SIZE sizeof(WORD)

void* OE_HostMalloc(size_t size)
{
    uint64_t argIn = size;
    uint64_t argOut = 0;

    if (__OE_OCall(OE_FUNC_MALLOC, argIn, &argOut) != OE_OK)
    {
        return NULL;
    }

    return (void*)argOut;
}

void* OE_HostCalloc(size_t nmemb, size_t size)
{
    void* ptr = OE_HostMalloc(nmemb * size);

    if (ptr)
        OE_Memset(ptr, 0, nmemb * size);

    return ptr;
}

void OE_HostFree(void* ptr)
{
    __OE_OCall(OE_FUNC_FREE, (uint64_t)ptr, NULL);
}

char* OE_HostStrdup(const char* str)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = OE_Strlen(str);

    if (!(p = OE_HostMalloc(len + 1)))
        return NULL;

    OE_Memcpy(p, str, len + 1);

    return p;
}

int OE_HostPrintf(const char* fmt, ...)
{
    char buf[1024];

    OE_va_list ap;
    OE_va_start(ap, fmt);
    int n = OE_Vsnprintf(buf, sizeof(buf), fmt, ap);
    OE_va_end(ap);

    OE_HostPrint(buf);

    return n;
}

int OE_HostPutchar(int c)
{
    int ret = -1;

    if (__OE_OCall(OE_FUNC_PUTCHAR, (uint64_t)c, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    return ret;
}

int OE_HostPuts(const char* str)
{
    int ret = -1;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (__OE_OCall(OE_FUNC_PUTS, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}

int OE_HostPrint(const char* str)
{
    int ret = -1;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (__OE_OCall(OE_FUNC_PRINT, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}
