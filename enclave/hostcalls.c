#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
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

void* OE_HostRealloc(void* ptr, size_t size)
{
    OE_ReallocArgs* argIn = NULL;
    uint64_t argOut = 0;

    /* Allocate host stack memory for the arguments */
    if (!(argIn = (OE_ReallocArgs*)OE_HostAllocForCallHost(
        sizeof(OE_ReallocArgs), 0, false)))
    {
        return NULL;
    }

    argIn->ptr = ptr;
    argIn->size = size;

    if (OE_OCall(OE_FUNC_REALLOC, (uint64_t)argIn, &argOut) != OE_OK)
    {
        return NULL;
    }

    return (void*)argOut;
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

int __OE_HostPrint(int device, const char* str, size_t len)
{
    int ret = -1;
    OE_PrintArgs* args = NULL;

    /* Reject invalid arguments */
    if ((device != 0 && device != 1) || !str)
        goto done;

    /* Determine the length of the string */
    if (len == (size_t)-1)
        len = OE_Strlen(str);

    /* Allocate space for the arguments followed by null-terminated string */
    if (!(args = (OE_PrintArgs*)OE_HostAllocForCallHost(
        sizeof(OE_PrintArgs) + len + 1, 0, false)))
    {
        goto done;
    }

    /* Initialize the arguments */
    args->device = device;
    args->str = (char*)(args + 1);
    OE_Memcpy(args->str, str, len);
    args->str[len] = '\0';

    /* Perform OCALL */
    if (OE_OCall(OE_FUNC_PRINT, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    /* Memory obtained by OE_HostStackMalloc() is released automatically */

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

    __OE_HostPrint(0, p, (size_t)-1);

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
