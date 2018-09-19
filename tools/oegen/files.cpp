// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "files.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int LoadFile(const char* path, size_t extraBytes, void** data, size_t* size)
{
    int rc = -1;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        *size = st.st_size;
    }

    /* Allocate memory */
    if (!(*data = malloc(*size + extraBytes)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        goto done;

    /* Zero-fill any extra bytes */
    if (extraBytes)
        memset((unsigned char*)*data + *size, 0, extraBytes);

    rc = 0;

done:

    if (rc != 0)
    {
        if (data && *data)
        {
            free(*data);
            *data = NULL;
        }

        if (size)
            *size = 0;
    }

    if (is)
        fclose(is);

    return rc;
}

int LoadFile(const char* path, size_t extraBytes, std::vector<char>& v)
{
    void* data;
    size_t size;

    if (LoadFile(path, extraBytes, &data, &size) != 0)
        return -1;

    v.insert(v.begin(), (char*)data, (char*)data + size + extraBytes);
    return 0;
}
