#include <stdio.h>
#include <string.h>

/* Wrappers to work around generated GCC fortification functions */

int __vfprintf_chk(FILE *stream, const char *format, va_list ap);

int vfprintf(FILE *stream, const char *format, va_list ap);

int __vfprintf_chk(FILE *stream, const char *format, va_list ap)
{
    return vfprintf(stream, format, ap);
}

void *__memset_chk(void *s, int c, size_t n);

void *__memset_chk(void *s, int c, size_t n)
{
    return memset(s, c, n);
}
