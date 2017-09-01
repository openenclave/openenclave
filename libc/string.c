#include <string.h>

int strcoll(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

size_t strxfrm(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n);
    return n;
}
