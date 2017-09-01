#include <wchar.h>

int wcscoll(const wchar_t *s1, const wchar_t *s2)
{
    return wcscmp(s1, s2);
}

size_t wcsxfrm(wchar_t *dest, const wchar_t *src, size_t n)
{
    wcsncpy(dest, src, n);
    return n;
}
