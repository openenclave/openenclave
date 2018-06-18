// #define __OE_NEED_TIME_CALLS
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/calls.h>
#include "../3rdparty/mbedtls/include/bits/mbedtls_libc.h"

static char* _strncpy(char* dest, const char* src, size_t n)
{
    char* p = dest;

    while (n-- && *src)
        *p++ = *src++;

    while (n--)
        *p++ = '\0';

    return dest;
}

static char* _strstr(const char* haystack, const char* needle)
{
    size_t hlen = oe_strlen(haystack);
    size_t nlen = oe_strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (oe_memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}

static void* _memmove(void* dest, const void* src, size_t n)
{
    char *p = (char*)dest;
    const char *q = (const char*)src;

    if (p != q && n > 0)
    {
        if (p <= q)
        {
            oe_memcpy(p, q, n);
        }
        else
        {
            for (q += n, p += n; n--; p--, q--)
                p[-1] = q[-1];
        }
    }

    return p;
}

static void* _malloc(size_t size)
{
    /* ATTN */
    return NULL;
}

static void _free(void* ptr)
{
    /* ATTN */
}

static void* _calloc(size_t nmemb, size_t size)
{
    /* ATTN */
    return NULL;
}

static void* _realloc(void* ptr, size_t size)
{
    /* ATTN */
    return NULL;
}

static int _vprintf(const char* fmt, va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(buf, sizeof(buf), fmt, ap);
        oe_va_end(ap);

        if (n < sizeof(buf))
        {
            __oe_host_print(0, p, (size_t)-1);
            goto done;
        }
    }

    /* If string was truncated, retry with correctly sized buffer */
    {
        char new_buf[n + 1];
        p = new_buf;

        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(p, n + 1, fmt, ap);
        oe_va_end(ap);

        __oe_host_print(0, p, (size_t)-1);
    }

done:
    return n;
}

static int _rand(void)
{
    /* ATTN */
    return 0;
}

#if 0
static time_t _time(time_t* tloc)
{
    time_t ret = 0;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;
    oe_gettimeofday_args_t* args = NULL;

    if (!(args = oe_host_calloc(1, sizeof(oe_gettimeofday_args_t))))
        goto done;

    args->ret = -1;
    args->tv = &args->tvbuf;
    args->tz = NULL;

    if (oe_ocall(OE_FUNC_GETTIMEOFDAY, (uint64_t)args, NULL, flags) != OE_OK)
        goto done;

    if (args->ret != 0)
        goto done;

    ret = args->tvbuf.tv_sec;

    if (tloc)
        *tloc = ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}
#endif

#if 0
static struct tm* _gmtime(const time_t* timep)
{
    /* ATTN */
    return NULL;
}
#endif

void oe_init_mbedtls()
{
    static mbedtls_libc_t _libc =
    {
        oe_strlen,
        oe_strcmp,
        oe_strncmp,
        _strncpy,
        _strstr,
        oe_memset,
        oe_memcpy,
        oe_memcmp,
        _memmove,
        _malloc,
        _free,
        _calloc,
        _realloc,
        oe_vsnprintf,
        _vprintf,
        _rand,
#if 0
        _time,
        _gmtime,
#endif
    };

    __mbedtls_libc = _libc;
}
