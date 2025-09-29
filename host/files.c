// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "fopen.h"

bool __oe_file_exists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0 ? true : false;
}

oe_result_t __oe_load_file(
    const char* path,
    size_t extra_bytes,
    void** data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            OE_RAISE(OE_NOT_FOUND);

        *size = (size_t)st.st_size;
    }

    /* Check for integer overflow */
    size_t total_size;
    OE_CHECK(oe_safe_add_sizet(*size, extra_bytes, &total_size));

    /* Allocate memory */
    *data = malloc(total_size);
    if (!*data)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Open the file */
    if (oe_fopen(&is, path, "rb") != 0)
        OE_RAISE(OE_NOT_FOUND);

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        OE_RAISE(OE_READ_FAILED);

    /* Zero-fill any extra bytes */
    if (extra_bytes)
        memset((unsigned char*)*data + *size, 0, extra_bytes);

    result = OE_OK;

done:
    if (result != OE_OK)
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

    return result;
}

oe_result_t __oe_load_pages(const char* path, oe_page_t** pages, size_t* npages)
{
    oe_result_t result = OE_UNEXPECTED;
    void* data = NULL;
    size_t size;

    /* Reject invalid parameters */
    if (!path || !pages || !npages)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the file into memory with zero extra bytes */
    OE_CHECK(__oe_load_file(path, 0, &data, &size));

    /* Fail if file size is not a multiple of the page size */
    if (size % OE_PAGE_SIZE)
        OE_RAISE(OE_FAILURE);

    /* Set the output parameters */
    *pages = ((oe_page_t*)data);
    *npages = size / OE_PAGE_SIZE;

    result = OE_OK;

done:

    if (result != OE_OK)
        free(data);

    return result;
}
