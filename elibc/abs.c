#include <stdlib.h>

int abs(int x)
{
    return __builtin_abs(x);
}

long labs(long x)
{
    return __builtin_labs(x);
}

long long llabs(long long x)
{
    return __builtin_llabs(x);
}
