#include <openenclave/enclave.h>

size_t OE_Strlen(const char* s)
{
    const char* p = s;

    while (*p++)
        ;

    return p - s;
}

size_t OE_Wcslen(const wchar_t* s)
{
    const wchar_t* p = s;

    while (*p++)
        ;

    return p - s;
}

int OE_Strcmp(const char* s1, const char* s2)
{
    while (*s1 && *s2)
    {
        int r = *s1++ - *s2++;

        if (r)
            return r;
    }

    if (*s1)
        return 1;

    if (*s2)
        return -1;

    return 0;
}

int OE_Wcscmp(const wchar_t* s1, const wchar_t* s2)
{
    while (*s1 && *s2)
    {
        int r = *s1++ - *s2++;

        if (r)
            return r;
    }

    if (*s1)
        return 1;

    if (*s2)
        return -1;

    return 0;
}

char *OE_Strcpy(char* dest, const char* src)
{
    char* p = (char*)dest;
    const char* q = (const char*)src;

    while (*q)
        *p++ = *q++;

    *p = '\0';

    return dest;
}

void *OE_Memcpy(void *dest, const void *src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

void *OE_Memset(void *s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = c;

    return s;
}

int OE_Memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char* p = (const unsigned char*)s1;
    const unsigned char* q = (const unsigned char*)s2;

    while (n--)
    {
        int r = *p++ - *q++;

        if (r)
            return r;
    }

    return 0;
}

char* OE_Strdup(const char* s)
{
    if (!s)
        return OE_NULL;

    size_t len = OE_Strlen(s);

    char* p = (char*)OE_Malloc(len + 1);

    if (!p)
        return OE_NULL;

    OE_Memcpy(p, s, len + 1);

    return p;
}
