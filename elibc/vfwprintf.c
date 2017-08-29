#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include "../3rdparty/musl/musl/src/internal/stdio_impl.h"

wint_t fputwc(wchar_t c, FILE *f);

int vfwprintf(FILE *stream, const wchar_t *fmt, va_list ap);

int fwide(FILE* stream, int mode);

#include "../3rdparty/musl/musl/src/stdio/vfwprintf.c"
