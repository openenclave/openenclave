#include <stdlib.h>
#include <locale.h>

long long int strtoll_l(const char *nptr, char **endptr, int base, locale_t loc)
{
    return strtoll(nptr, endptr, base);
}
