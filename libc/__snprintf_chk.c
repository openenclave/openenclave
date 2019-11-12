// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// GCC sometimes replaces snprintf() calls with __snprintf_chk() calls. In glibc
// this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vsnprintf().
int __snprintf_chk(
    char* s,
    size_t maxlen,
    int flag,
    size_t slen,
    const char* format,
    ...)
{
    va_list ap;

    OE_UNUSED(flag);

    if (slen < maxlen)
    {
        assert("__snprintf_chk(): buffer overflow" == NULL);
        abort();
    }

    va_start(ap, format);
    int ret = vsnprintf(s, maxlen, format, ap);
    va_end(ap);

    return ret;
}

#endif // __GNUC__
