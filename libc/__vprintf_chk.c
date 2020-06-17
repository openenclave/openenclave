// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

#include <openenclave/enclave.h>
#include <stdio.h>

// GCC sometimes replaces vprintf() calls with __vprintf_chk() calls. In
// glibc this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vprintf().
int __vprintf_chk(int flag, const char* format, va_list ap)
{
    OE_UNUSED(flag);
    return vprintf(format, ap);
}

#endif // __GNUC__
