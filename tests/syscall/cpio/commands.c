// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include "commands.h"
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "strarr.h"
#include "trace.h"

int oe_lsr(const char* root, oe_strarr_t* paths)
{
    int ret = -1;
    DIR* dir = NULL;
    struct dirent* ent;
    char path[PATH_MAX];
    oe_strarr_t dirs = OE_STRARR_INITIALIZER;

    /* Check parameters */
    if (!root || !paths)
        GOTO(done);

    /* Open the directory */
    if (!(dir = opendir(root)))
        GOTO(done);

    /* For each entry */
    while ((ent = readdir(dir)))
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        strlcpy(path, root, sizeof(path));

        if (strcmp(root, "/") != 0)
            strlcat(path, "/", sizeof(path));

        strlcat(path, ent->d_name, sizeof(path));

        /* Append to paths[] array */
        if (oe_strarr_append(paths, path) != 0)
            GOTO(done);

        /* Append to dirs[] array */
        if (ent->d_type & DT_DIR)
        {
            if (oe_strarr_append(&dirs, path) != 0)
                GOTO(done);
        }
    }

    /* Recurse into child directories */
    {
        size_t i;

        for (i = 0; i < dirs.size; i++)
        {
            if (oe_lsr(dirs.data[i], paths) != 0)
                GOTO(done);
        }
    }

    ret = 0;

done:

    if (dir)
        closedir(dir);

    oe_strarr_release(&dirs);

    if (ret != 0)
    {
        oe_strarr_release(paths);
        memset(paths, 0, sizeof(oe_strarr_t));
    }

    return ret;
}

int oe_cmp(const char* path1, const char* path2)
{
    int ret = -1;
    struct stat st1;
    struct stat st2;
    uint8_t buf1[512];
    uint8_t buf2[512];
    FILE* is1 = NULL;
    FILE* is2 = NULL;
    size_t size = 0;

    if (!path1 || !path2)
        GOTO(done);

    if (stat(path1, &st1) != 0)
        GOTO(done);

    if (stat(path2, &st2) != 0)
        GOTO(done);

    if (S_ISDIR(st1.st_mode) && !S_ISDIR(st2.st_mode))
        GOTO(done);

    if (!S_ISDIR(st1.st_mode) && S_ISDIR(st2.st_mode))
        GOTO(done);

    if (S_ISREG(st1.st_mode) && !S_ISREG(st2.st_mode))
        GOTO(done);

    if (!S_ISREG(st1.st_mode) && S_ISREG(st2.st_mode))
        GOTO(done);

    if (S_ISDIR(st1.st_mode))
    {
        ret = 0;
        GOTO(done);
    }

    if (st1.st_size != st2.st_size)
        GOTO(done);

    if (!(is1 = fopen(path1, "rb")))
        GOTO(done);

    if (!(is2 = fopen(path2, "rb")))
        GOTO(done);

    for (;;)
    {
        size_t n1 = fread(buf1, 1, sizeof(buf1), is1);
        size_t n2 = fread(buf2, 1, sizeof(buf2), is2);

        if (n1 != n2)
            GOTO(done);

        if (memcmp(buf1, buf2, n1) != 0)
            GOTO(done);

        size += n1;
    }

    if (size != (size_t)st1.st_size)
    {
        GOTO(done);
    }

    ret = 0;

done:

    if (is1)
        fclose(is1);

    if (is2)
        fclose(is2);

    return ret;
}
