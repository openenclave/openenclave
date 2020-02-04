// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>

// GCC sometimes replaces vsnprintf() calls with __vsnprintf_chk() calls. In
// glibc this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vsnprintf().
int __vsnprintf_chk(
    char* s,
    size_t maxlen,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    OE_UNUSED(flag);

    if (slen < maxlen)
    {
        assert("__vsnprintf_chk(): buffer overflow" == NULL);
        abort();
    }

    return vsnprintf(s, maxlen, format, ap);
}

#endif // __GNUC__
