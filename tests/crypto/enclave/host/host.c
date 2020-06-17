// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <io.h>
#else
#error "Unsupported OS platform"
#endif

#include "crypto_u.h"

int f_open(char* path, int flags, int mode)
{
#if defined(_WIN32)
    /* On Windows, files must be opened as binary instead of text explicitly,
     * otherwise file reads will terminate on the SUB character (0x1A) as EOF.
     * This also requires use of the ISO ('_' prefixed) and not POSIX versions
     * of the functions on Windows.
     *
     * Ideally, the callers of fopen in read_file.c should be using "rb" as the
     * file flags, but the MUSL implementation ignores the binary flag and does
     * not pass it on to the syscall hook for handling. This means that PEM are
     * also processed as binary (as they would be equivalently on Linux).
     */
    flags |= _O_BINARY;
#pragma warning(push)
#pragma warning(disable : 4996)
    return _open(path, flags, mode);
#pragma warning(pop)
#else
    return open(path, flags, mode);
#endif
}

int f_openat(int dirfd, char* path, int flags, int mode)
{
#if defined(_WIN32)
    return -1;
#else
    return openat(dirfd, path, flags, mode);
#endif
}

int f_read(int fd, char* ptr, size_t len)
{
#if defined(_WIN32)
    return (int)_read(fd, ptr, (int)len);
#else
    return (int)read(fd, ptr, len);
#endif
}

int f_close(int fd)
{
#if (defined(_WIN32))
    return _close(fd);
#else
    return close(fd);
#endif
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_crypto_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_crypto_enclave(): result=%u", result);
    }

    if ((result = test(enclave)) != OE_OK)
    {
        oe_put_err("test() failed: result=%u", result);
    }

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave() failed: %u\n", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
