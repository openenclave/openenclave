#include <wchar.h>

int wcscoll(const wchar_t* s1, const wchar_t* s2)
{
    return wcscmp(s1, s2);
}

int wcscoll_l(const wchar_t* s1, const wchar_t* s2, locale_t loc)
{
    return wcscoll(s1, s2);
}

size_t wcsxfrm(wchar_t* dest, const wchar_t* src, size_t n)
{
    wcsncpy(dest, src, n);
    return n;
}

size_t wcsxfrm_l(wchar_t* dest, const wchar_t* src, size_t n, locale_t loc)
{
    return wcsxfrm(dest, src, n);
}
