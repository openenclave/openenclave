#include <stdio.h>
#include <wchar.h>

wint_t __fputwc_unlocked(wchar_t c, FILE *f);

wint_t fputwc(wchar_t c, FILE *f);

#include "../3rdparty/musl/musl/src/stdio/fputwc.c"
