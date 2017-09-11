#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/print.h>
#include "td.h"

void* OE_HostMalloc(size_t size)
{
    uint64_t argIn = size;
    uint64_t argOut = 0;

    if (OE_OCall(OE_FUNC_MALLOC, argIn, &argOut) != OE_OK)
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
    OE_OCall(OE_FUNC_FREE, (uint64_t)ptr, NULL);
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

int __OE_HostPutchar(int c)
{
    int ret = -1;

    if (OE_OCall(OE_FUNC_PUTCHAR, (uint64_t)c, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    return ret;
}

int __OE_HostPuts(const char* str)
{
    int ret = -1;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (OE_OCall(OE_FUNC_PUTS, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}

int __OE_HostPrint(const char* str)
{
    int ret = -1;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (OE_OCall(OE_FUNC_PRINT, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}

int __OE_HostVprintf(const char* fmt, OE_va_list ap_)
{
    char buf[256];
    char *p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        OE_va_list ap;
        OE_va_copy(ap, ap_);
        n = OE_Vsnprintf(buf, sizeof(buf), fmt, ap);
        OE_va_end(ap);
    }

    /* If string was truncated, retry with correctly sized buffer */
    if (n >= sizeof(buf))
    {
        if (!(p = OE_StackAlloc(n + 1, 0)))
            return -1;
        
        OE_va_list ap;
        OE_va_copy(ap, ap_);
        n = OE_Vsnprintf(p, n + 1, fmt, ap);
        OE_va_end(ap);
    }

    __OE_HostPrint(p);

    return n;
}

int OE_HostPrintf(const char* fmt, ...)
{
    int n;

    OE_va_list ap;
    OE_va_start(ap, fmt);
    n = __OE_HostVprintf(fmt, ap);
    OE_va_end(ap);

    return n;
}
