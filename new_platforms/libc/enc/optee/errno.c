#include <errno.h>

static int g_errno = 0;

int *___errno_location(void)
{
    return &g_errno;
}
