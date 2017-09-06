#include <wchar.h>

size_t wcsxfrm_l(wchar_t *dest, const wchar_t *src, size_t n, locale_t loc)
{
    return wcsxfrm(dest, src, n);
}
