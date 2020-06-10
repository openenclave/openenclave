// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _XOPEN_SOURCE 500

#include <ftw.h>
#include <unistd.h>

static int do_delete(
    const char* path,
    const struct stat* sb,
    int tflag,
    struct FTW* ftwbuf)
{
    switch (tflag)
    {
        case FTW_D:
        case FTW_DNR:
        case FTW_DP:
            rmdir(path);
            break;
        default:
            unlink(path);
            break;
    }

    return (0);
}
int recursive_rmdir(const char* path)
{
    // DFS depth is set to 64.
    return nftw(path, do_delete, 64, FTW_DEPTH);
}
