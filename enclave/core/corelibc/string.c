// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/corelibc/errno.h>
#include <openenclave/internal/corelibc/string.h>

typedef struct _error_string
{
    int num;
    const char* str;
}
error_string_t;

static const error_string_t _error_strings[] = {
    {E2BIG, "Argument list too long"},
    {EACCES, "Permission denied"},
    {EADDRINUSE, "Address in use"},
    {EADDRNOTAVAIL, "Address not available"},
    {EAFNOSUPPORT, "Address family not supported"},
    {EAGAIN, "Resource unavailable, try again"},
    {EALREADY, "Connection already in progress"},
    {EBADF, "Bad file descriptor"},
    {EBADMSG, "Bad message"},
    {EBUSY, "Device or resource busy"},
    {ECANCELED, "Operation canceled"},
    {ECHILD, "No child processes"},
    {ECONNABORTED, "Connection aborted"},
    {ECONNREFUSED, "Connection refused"},
    {ECONNRESET, "Connection reset"},
    {EDEADLK, "Resource deadlock would occur"},
    {EDESTADDRREQ, "Destination address required"},
    {EDOM, "Math argument out of domain of function"},
    {EDQUOT, "Reserved"},
    {EEXIST, "File exists"},
    {EFAULT, "Bad address"},
    {EFBIG, "File too large"},
    {EHOSTUNREACH, "Host is unreachable"},
    {EIDRM, "Identifier removed"},
    {EILSEQ, "Illegal byte sequence"},
    {EINPROGRESS, "Operation in progress"},
    {EINTR, "Interrupted function"},
    {EINVAL, "Invalid argument"},
    {EIO, "I/O error"},
    {EISCONN, "Socket is connected"},
    {EISDIR, "Is a directory"},
    {ELOOP, "Too many levels of symbolic links"},
    {EMFILE, "Too many open files"},
    {EMLINK, "Too many links"},
    {EMSGSIZE, "Message too large"},
    {EMULTIHOP, "Reserved"},
    {ENAMETOOLONG, "Filename too long"},
    {ENETDOWN, "Network is down"},
    {ENETRESET, "Connection aborted by network"},
    {ENETUNREACH, "Network unreachable"},
    {ENFILE, "Too many files open in system"},
    {ENOBUFS, "No buffer space available"},
    {ENODATA, "No message available on STREAM queue"},
    {ENODEV, "No such device"},
    {ENOENT, "No such file or directory"},
    {ENOEXEC, "Executable file format error"},
    {ENOLCK, "No locks available"},
    {ENOLINK, "Reserved"},
    {ENOMEM, "Not enough space"},
    {ENOMSG, "No message of the desired type"},
    {ENOPROTOOPT, "Protocol not available"},
    {ENOSPC, "No space left on device"},
    {ENOSR, "No STREAM resources"},
    {ENOSTR, "Not a STREAM"},
    {ENOSYS, "Function not supported"},
    {ENOTCONN, "The socket is not connected"},
    {ENOTDIR, "Not a directory"},
    {ENOTEMPTY, "Directory not empty"},
    {ENOTSOCK, "Not a socket"},
    {ENOTSUP, "Not supported"},
    {ENOTTY, "Inappropriate I/O control operation"},
    {ENXIO, "No such device or address"},
    {EOPNOTSUPP, "Operation not supported on socket"},
    {EOVERFLOW, "Value too large to be stored in data type"},
    {EPERM, "Operation not permitted"},
    {EPIPE, "Broken pipe"},
    {EPROTO, "Protocol error"},
    {EPROTONOSUPPORT, "Protocol not supported"},
    {EPROTOTYPE, "Protocol wrong type for socket"},
    {ERANGE, "Result too large"},
    {EROFS, "Read-only file system"},
    {ESPIPE, "Invalid seek"},
    {ESRCH, "No such process"},
    {ESTALE, "Reserved"},
    {ETIME, "Stream ioctl() timeout"},
    {ETIMEDOUT, "Connection timed out"},
    {ETXTBSY, "Text file busy"},
    {EWOULDBLOCK, "Operation would block"},
    {EXDEV, "Cross-device link"},
};

static const char _unknown_error_string[] = "Unknown error";

size_t oe_strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return p - s;
    if (!p[1])
        return p - s + 1;
    if (!p[2])
        return p - s + 2;
    if (!p[3])
        return p - s + 3;
    if (!p[4])
        return p - s + 4;
    if (!p[5])
        return p - s + 5;

    /* Unreachable */
    return 0;
}

size_t oe_strnlen(const char* s, size_t n)
{
    const char* p = s;

    while (n-- && *p)
        p++;

    return p - s;
}

int oe_strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int oe_strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

char* oe_strncpy(char* dest, const char* src, size_t n)
{
    char* p = dest;

    while (n-- && *src)
        *p++ = *src++;

    while (n--)
        *p++ = '\0';

    return dest;
}

size_t oe_strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return src - start;
}

size_t oe_strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

char* oe_strstr(const char* haystack, const char* needle)
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

char* oe_strerror(int errnum)
{
    for (size_t i = 0; i < OE_COUNTOF(_error_strings); i++)
    {
        if (_error_strings[i].num == errnum)
            return (char*)_error_strings[i].str;
    }

    return (char*)_unknown_error_string;
}

int oe_strerror_r(int errnum, char* buf, size_t buflen)
{
    const char* str = NULL;

    for (size_t i = 0; i < OE_COUNTOF(_error_strings); i++)
    {
        if (_error_strings[i].num == errnum)
        {
            str = _error_strings[i].str;
            break;
        }
    }

    if (!str)
        str = _unknown_error_string;

    return oe_strlcpy(buf, str, buflen) >= buflen ? ERANGE : 0;
}

static void* _memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

void* oe_memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

#if defined(__GNUC__)

    while (n >= 1024)
    {
        __builtin_memcpy(p, q, 1024);
        n -= 1024;
        p += 1024;
        q += 1024;
    }

    while (n >= 256)
    {
        __builtin_memcpy(p, q, 256);
        n -= 256;
        p += 256;
        q += 256;
    }

    while (n >= 64)
    {
        __builtin_memcpy(p, q, 64);
        n -= 64;
        p += 64;
        q += 64;
    }

    while (n >= 16)
    {
        __builtin_memcpy(p, q, 16);
        n -= 16;
        p += 16;
        q += 16;
    }

#endif

    _memcpy(p, q, n);

    return dest;
}

static void* _memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = c;

    return s;
}

void* oe_memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

#if defined(__GNUC__)

    while (n >= 1024)
    {
        __builtin_memset(p, c, 1024);
        n -= 1024;
        p += 1024;
    }

    while (n >= 256)
    {
        __builtin_memset(p, c, 256);
        n -= 256;
        p += 256;
    }

    while (n >= 64)
    {
        __builtin_memset(p, c, 64);
        n -= 64;
        p += 64;
    }

    while (n >= 16)
    {
        __builtin_memset(p, c, 16);
        n -= 16;
        p += 16;
    }

#endif

    _memset(p, c, n);

    return s;
}

static int _memcmp(const void* s1, const void* s2, size_t n)
{
    const unsigned char* p = (const unsigned char*)s1;
    const unsigned char* q = (const unsigned char*)s2;

    while (n--)
    {
        int r = *p++ - *q++;

        if (r)
            return r;
    }

    return 0;
}

int oe_memcmp(const void* s1, const void* s2, size_t n)
{
    return _memcmp(s1, s2, n);
}

static void* _memmove(void* dest, const void* src, size_t n)
{
    char* p = (char*)dest;
    const char* q = (const char*)src;

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

void* oe_memmove(void* dest, const void* src, size_t n)
{
    return _memmove(dest, src, n);
}
