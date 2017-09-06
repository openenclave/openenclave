#include <wchar.h>

int wcscoll_l(const wchar_t *s1, const wchar_t *s2, locale_t loc)
{
    return wcscoll(s1, s2);
}
