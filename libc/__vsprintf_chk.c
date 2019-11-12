// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>

// GCC sometimes replaces vsprintf() calls with __vsprintf_chk() calls. In
// glibc this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vsprintf().
int __vsprintf_chk(
    char* s,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    OE_UNUSED(flag);

    if (slen == 0)
    {
        assert("__vsprintf_chk(): buffer overflow" == NULL);
        abort();
    }

    return vsprintf(s, format, ap);
}

#endif // __GNUC__
