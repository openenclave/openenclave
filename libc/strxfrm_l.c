#include <string.h>

size_t strxfrm_l(char *dest, const char *src, size_t n, locale_t loc)
{
    return strxfrm(dest, src, n);
}
