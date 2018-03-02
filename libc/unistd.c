#include <errno.h>
#include <unistd.h>

long sysconf(int name)
{
    errno = EINVAL;
    return -1;
}
