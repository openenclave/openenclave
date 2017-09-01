#include <stdio.h>
#include <stdarg.h>

int vfprintf(FILE *restrict f, const char *restrict fmt, va_list ap);

#include "../3rdparty/musl/musl/src/stdio/vsnprintf.c"
