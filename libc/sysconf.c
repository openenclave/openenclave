#include <unistd.h>
#include <errno.h>

long sysconf(int name)
{
    errno = EINVAL;
    return -1;
}
