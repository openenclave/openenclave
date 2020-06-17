// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// GCC sometimes replaces sprintf() calls with __sprintf_chk() calls. In glibc
// this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vsprintf().
int __sprintf_chk(char* s, int flag, size_t slen, const char* format, ...)
{
    va_list ap;

    OE_UNUSED(flag);

    if (slen == 0)
    {
        assert("__sprintf_chk(): buffer overflow" == NULL);
        abort();
    }

    va_start(ap, format);
    int ret = vsprintf(s, format, ap);
    va_end(ap);

    return ret;
}

#endif // __GNUC__
