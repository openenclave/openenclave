// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _WIN32
#pragma warning(disable : 4996)
#endif

#include <assert.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "myfileio.h"

int mbed_test_open(const char* path, int flags, mode_t mode)
{
    return open(path, flags, mode);
}

ssize_t mbed_test_read(int fd, char* buf, size_t buf_len)
{
    return read(fd, buf, (int)buf_len);
}

int mbed_test_close(int fd)
{
    return close(fd);
}

int mbed_test_lseek(int fd, int offset, int whence)
{
    return lseek(fd, offset, whence);
}
