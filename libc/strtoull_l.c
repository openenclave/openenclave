#include <stdlib.h>
#include <locale.h>

unsigned long long int strtoull_l(
    const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtoull(nptr, endptr, base);
}
