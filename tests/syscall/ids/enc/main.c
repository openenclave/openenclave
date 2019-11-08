// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int run_main(const char* tmp_dir)
{
    int ret = -1;
    FILE* stream = NULL;
    char path[PATH_MAX];
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    /* Create the temporary directory. */
    if (mkdir(tmp_dir, 0777) != 0)
    {
        fprintf(stderr, "mkdir() failed: %s\n", tmp_dir);
        goto done;
    }

    /* Form the path to the new file. */
    strcpy(path, tmp_dir);
    strcat(path, "/myfile");

    /* Create a file with the letters of the alphabet. */
    {
        if (!(stream = fopen(path, "w")))
        {
            fprintf(stderr, "fopen() failed: %s\n", path);
            goto done;
        }

        size_t n = fwrite(alphabet, 1, sizeof(alphabet), stream);

        if (n != sizeof(alphabet))
        {
            fprintf(stderr, "fwrite() failed: %s\n", path);
            goto done;
        }

        fclose(stream);
        stream = NULL;

        printf("Created %s\n", path);
    }

    /* Check the size of the file. */
    {
        struct stat buf;

        if (!(stat(path, &buf) == 0 && buf.st_size == sizeof(alphabet)))
        {
            fprintf(stderr, "stat() failed: %s\n", path);
            goto done;
        }
    }

    /* Create a file with the letters of the alphabet. */
    {
        char buf[sizeof(alphabet)];

        if (!(stream = fopen(path, "r")))
        {
            fprintf(stderr, "fopen() failed: %s\n", path);
            goto done;
        }

        size_t n = fread(buf, 1, sizeof(alphabet), stream);

        if (n != sizeof(alphabet))
        {
            fprintf(stderr, "fread() failed: %s\n", path);
            goto done;
        }

        if (memcmp(alphabet, buf, sizeof(alphabet)) != 0)
        {
            fprintf(stderr, "memcmp() failed\n");
            goto done;
        }

        fclose(stream);
        stream = NULL;
    }

    ret = 0;

done:

    if (stream)
        fclose(stream);

    return ret;
}
