#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "strings.h"

long Test1(const char* str)
{
    for (long i = 0; i < nstrings; i++)
    {
        if (strcmp(strings[i].str, str) == 0)
        {
            return i;
        }
    }

    return -1;
}

static __inline__ uint64_t StrCode(const char* s, uint64_t n)
{
    return (uint64_t)s[0] | ((uint64_t)s[n-1] << 8) | ((uint64_t)n << 16);
}

void Setup()
{
    for (long i = 0; i < nstrings; i++)
        strings[i].code = StrCode(strings[i].str, strlen(strings[i].str));
}

long Test2(const char* s)
{
    static uint64_t initialized;

    if (initialized == 0)
        Setup();

    if (*s)
    {
        uint64_t n = strlen(s);
        uint64_t code = StrCode(s, n);

        for (long i = 0; i < nstrings; i++)
        {
            const Pair* p = &strings[i];

            if (p->code == code && memcmp(&p->str[1], &s[1], n-2) == 0)
                return i;
        }
    }

    return -1;
}

int main()
{
    long sum = 0;

    for (size_t i = 0; i < 3000000; i++)
    {
        sum += Test2("xxxtypeinfo.o");
    }

    printf("sum{%ld}\n", sum);

    return 0;
}
