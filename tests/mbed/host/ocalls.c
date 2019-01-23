// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(_WIN32)
    #include <io.h>
    #include <process.h>
    #include <direct.h>
    typedef unsigned mode_t;
#else
    #include <sys/uio.h>
    #include <unistd.h>
#endif
#include "mbed_u.h"

int mbed_test_open(const char* path, int flags, mode_t mode)
{
    return open(path, flags, mode);
}

ssize_t mbed_test_read(int fd, char* buf, size_t buf_len)
{
    return read(fd, buf, buf_len);
}

int mbed_test_close(int fd)
{
    return close(fd);
}
