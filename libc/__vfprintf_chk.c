#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

// GCC sometimes replaces vfpintf() calls with __vfprintf_chk() calls. In glibc 
// this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which causes // glibc to perform various checks on the output stream. Since MUSL has no 
// equivalent flag, this implementation simply calls vfprintf().
int __vfprintf_chk(FILE *stream, const char *format, va_list ap)
{
    return vfprintf(stream, format, ap);
}
