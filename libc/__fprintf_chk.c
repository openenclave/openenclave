// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>

// GCC sometimes replaces fprintf() calls with __fprintf_chk() calls. In glibc
// this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vfprintf().
int __fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;

    OE_UNUSED(flag);

    va_start(ap, format);
    int ret = vfprintf(stream, format, ap);
    va_end(ap);

    return ret;
}

#endif // __GNUC__
