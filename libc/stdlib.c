#include <stdlib.h>
#include <locale.h>
#include <stdio.h>

long long int strtoll_l(
    const char *nptr, 
    char **endptr, 
    int base, 
    locale_t loc)
{
    return strtoll(nptr, endptr, base);
}

unsigned long long int strtoull_l(
    const char *nptr, 
    char **endptr, 
    int base, 
    locale_t loc)
{
    return strtoull(nptr, endptr, base);
}
