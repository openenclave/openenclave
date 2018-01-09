#include "fopen.h"
#include <errno.h>
#include <stdio.h>

int OE_Fopen(
    FILE** fp,
    const char* path,
    const char* mode)
{
#if defined(__linux__)

    if (!fp)
        return EINVAL;

    if ((*fp = fopen(path, mode)) == NULL)
        return errno;

    return 0;

#elif defined(_MSC_VER)

    return fopen_s(fp, path, mode);

#endif
}
