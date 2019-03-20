#include "locale_impl.h"

char* strerror_l(int errnum, locale_t loc)
{
    (void)errnum;
    (void)loc;

    return "[ERROR STRING PLACEHOLDER]";
}

char* strerror(int errnum)
{
    (void)errnum;

    return "[ERROR STRING PLACEHOLDER]";
}
