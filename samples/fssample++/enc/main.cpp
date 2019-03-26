// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#undef OE_BUILD_ENCLAVE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, const char* argv[])
{
    FILE* stream;
    char tmp_dir[PATH_MAX];
    char path[PATH_MAX];
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s tmp-dir\n", argv[0]);
        exit(1);
    }

    /* Create the temporary directory. */
    {
        strcpy(tmp_dir, argv[1]);

        if (mkdir(tmp_dir, 0777) != 0)
        {
            fprintf(stderr, "mkdir() failed\n");
            exit(1);
        }
    }

    /* Form the path to the new file. */
    strcpy(path, tmp_dir);
    strcat(path, "/myfile");

    /* Create a file with the letters of the alphabet. */
    {
        if (!(stream = fopen(path, "w")))
        {
            fprintf(stderr, "fopen() failed: %s\n", path);
            exit(1);
        }

        size_t n = fwrite(alphabet, 1, sizeof(alphabet), stream);

        if (n != sizeof(alphabet))
        {
            fprintf(stderr, "fwrite() failed: %s\n", path);
            exit(1);
        }

        fclose(stream);

        printf("Created %s\n", path);
    }

    /* Check the size of the file. */
    {
        struct stat buf;

        if (!(stat(path, &buf) == 0 && buf.st_size == sizeof(alphabet)))
        {
            fprintf(stderr, "stat() failed: %s\n", path);
            exit(1);
        }
    }

    /* Create a file with the letters of the alphabet. */
    {
        char buf[sizeof(alphabet)];

        if (!(stream = fopen(path, "r")))
        {
            fprintf(stderr, "fopen() failed: %s\n", path);
            exit(1);
        }

        size_t n = fread(buf, 1, sizeof(alphabet), stream);

        if (n != sizeof(alphabet))
        {
            fprintf(stderr, "fread() failed: %s\n", path);
            exit(1);
        }

        if (memcmp(alphabet, buf, sizeof(alphabet)) != 0)
        {
            fprintf(stderr, "memcmp() failed\n");
            exit(1);
        }

        fclose(stream);
    }

    return 0;
}
