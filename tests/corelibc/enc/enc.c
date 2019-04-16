// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <limits.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _OE_STDIO_H
#error "Please include the stdio.h from corelibc."
#endif

static const char* _lines[] = {
    "",
    "a",
    "",
    "bb",
    "",
    "ccc",
    "",
    "dddd",
    "",
};

static const size_t _nlines = OE_COUNTOF(_lines);

static void _create_file(const char* tmp_dir)
{
    FILE* stream;
    char path[PATH_MAX];

    strlcpy(path, tmp_dir, sizeof(path));
    strlcat(path, "/myfile", sizeof(path));

    OE_TEST((stream = fopen(path, "w")));

    for (size_t i = 0; i < _nlines; i++)
        fprintf(stream, "%s\n", _lines[i]);

    fclose(stream);

    printf("Created %s\n", path);
}

static void _verify_file(const char* tmp_dir)
{
    FILE* stream;
    char path[PATH_MAX];
    char buf[1024];
    size_t i;

    strlcpy(path, tmp_dir, sizeof(path));
    strlcat(path, "/myfile", sizeof(path));

    OE_TEST((stream = fopen(path, "r")));

    for (i = 0; (fgets(buf, sizeof(buf), stream)); i++)
    {
        OE_TEST(i < _nlines);

        /* Remove the trailing newline. */
        {
            char* end = buf + strlen(buf);

            if (end[-1] == '\n')
                end[-1] = '\0';
        }

        OE_TEST(strcmp(buf, _lines[i]) == 0);
    }

    OE_TEST(i == _nlines);

    fclose(stream);

    printf("Verified %s\n", path);
}

static void _test_printf(void)
{
    char buf[1024];

    snprintf(buf, sizeof(buf), "%.5s", "1234567890");
    OE_TEST(strcmp(buf, "12345") == 0);

    snprintf(buf, sizeof(buf), "%.5s", "");
    OE_TEST(strcmp(buf, "") == 0);
}

static void _test_strtol(void)
{
    long x = strtol("-0x0020", NULL, 16);

    printf("x=%ld\n", x);
}

void test_corelibc(const char* tmp_dir)
{
    OE_TEST(tmp_dir != NULL);

    OE_TEST(oe_load_module_hostfs() == OE_OK);

    if (mount("/", "/", "hostfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    /* Create the temporary directory. */
    OE_TEST(mkdir(tmp_dir, 0777) == 0);

    /* Create the new file. */
    _create_file(tmp_dir);

    /* Read the file back and verify it. */
    _verify_file(tmp_dir);

    _test_printf();

    _test_strtol();

    if (umount("/") != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
