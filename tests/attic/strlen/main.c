#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

size_t Strlen(const char* s);
size_t Strlen1(const char* s);
size_t Strlen2(const char* s);
size_t Strlen3(const char* s);
size_t Strlen4(const char *s);

int main()
{
    long x;
    const char* p = "abcdefghijklmnopqrstuvwxyz";
    long y;
    size_t sum = 0;

    y = 0;
    x = 0;

#if 0
    {
        char buf[65];
        *buf = '\0';

        for (size_t i = 0; i < sizeof(buf) - 1; i++)
        {
            strcat(buf, "A");
            assert(Strlen3(buf) == strlen(buf));
        }
    }
#endif

    for (size_t i = 0; i < 300000000; i++)
    {
        sum += Strlen2(p);
    }

    printf("sum{%ld}\n", sum);
    assert(sum == 7800000000);
    assert(x == y);

    return 0;
}
