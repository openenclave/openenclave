#include "strings.h"
#include <string.h>
#include <stdlib.h>

char* Strdup(const char* str)
{
#if defined(__linux__)
    return strdup(str);
#elif defined(_MSC_VER)
    return _strdup(str);
#endif
}

size_t Strlcpy(
    char* dest, 
    const char* src, 
    size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return src - start;
}

size_t Strlcat(
    char* dest, 
    const char* src, 
    size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}
