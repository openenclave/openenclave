#include <openenclave/internal/enclavelibc.h>

int* __errno_location()
{
    return __oe_errno_location();
}
