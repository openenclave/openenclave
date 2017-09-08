#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <openenclave/enclave.h>

int strcoll(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

int strcoll_l(const char *s1, const char *s2, locale_t loc)
{
    return strcoll(s1, s2);
}

size_t strxfrm(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n);
    return n;
}

char* strdup(const char* s)
{
    if (!s)
        return NULL;

    size_t len = strlen(s);

    char* p = (char*)malloc(len + 1);

    if (!p)
        return NULL;

    memcpy(p, s, len + 1);

    return p;
}

size_t strxfrm_l(char *dest, const char *src, size_t n, locale_t loc)
{
    return strxfrm(dest, src, n);
}
