// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Define a TEST() macro that bypasses use of stderr and stdout devices.
// clang-format off
#define TEST(COND)                                 \
    do                                             \
    {                                              \
        if (!(COND))                               \
        {                                          \
            oe_host_printf(                        \
                "TEST failed: %s(%u): %s(): %s\n", \
                __FILE__,                          \
                __LINE__,                          \
                __FUNCTION__,                      \
                #COND);                            \
            oe_abort();                            \
        }                                          \
    }                                              \
    while(0)
// clang-format on

void test_dup(const char* tmp_dir)
{
    int fd;
    char path[PATH_MAX];
    const char MESSAGE[] = "This is STDOUT\n";

    printf("tmp_dir=%s\n", tmp_dir);

    TEST(oe_load_module_host_file_system() == OE_OK);

    TEST(mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) == 0);

    /* Create tmp_dir if non-existent. */
    {
        struct stat buf;

        TEST(tmp_dir);

        if (stat(tmp_dir, &buf) == 0)
            TEST(S_ISDIR(buf.st_mode));
        else
            TEST(mkdir(tmp_dir, 0777) == 0);
    }

    /* Create a file to replace STDERR. */
    {
        strlcpy(path, tmp_dir, sizeof(path));
        strlcat(path, "/STDERR", sizeof(path));
        fd = open(path, (O_WRONLY | O_CREAT | O_TRUNC), 0666);
        TEST(fd >= 0);

        printf("Created %s\n", path);
    }

    /* Redirect STDERR to the file given by fd. */
    TEST(close(STDERR_FILENO) == 0);

    /* Duplicate the file descriptor to first available descriptor. */
    TEST(dup(fd) == STDERR_FILENO);

    /* Write to STDERR, hence to fd. */
    fprintf(stderr, MESSAGE);

    /* Close the file. */
    TEST(close(fd) == 0);

    /* Reopen the file and verify that it contains the message. */
    {
        char buf[sizeof(MESSAGE)];
        ssize_t bytes_read;

        TEST((fd = open(path, O_RDONLY)) >= 0);
        bytes_read = read(fd, buf, sizeof(buf));
        TEST(bytes_read == sizeof(MESSAGE) - 1);
        TEST(memcmp(buf, MESSAGE, (size_t)bytes_read) == 0);
        TEST(close(fd) == 0);
    }

    TEST(umount("/") == 0);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
