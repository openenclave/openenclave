#include <openenclave/bits/files.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "fopen.h"

bool __OE_FileExists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0 ? true : false;
}

OE_Result __OE_LoadFile(const char* path, size_t extraBytes, void** data, size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            OE_THROW(OE_NOT_FOUND);

        *size = st.st_size;
    }

    /* Allocate memory */
    if (!(*data = malloc(*size + extraBytes)))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Open the file */
    if (OE_Fopen(&is, path, "rb") != 0)
        OE_THROW(OE_NOT_FOUND);

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        OE_THROW(OE_READ_FAILED);

    /* Zero-fill any extra bytes */
    if (extraBytes)
        memset((unsigned char*)*data + *size, 0, extraBytes);

    result = OE_OK;

OE_CATCH:

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

OE_Result __OE_LoadPages(const char* path, OE_Page** pages, size_t* npages)
{
    OE_Result result = OE_UNEXPECTED;
    void* data = NULL;
    size_t size;

    /* Reject invalid parameters */
    if (!path || !pages || !npages)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Load the file into memory with zero extra bytes */
    OE_TRY(__OE_LoadFile(path, 0, &data, &size));

    /* Fail if file size is not a multiple of the page size */
    if (size % OE_PAGE_SIZE)
        OE_THROW(OE_FAILURE);

    /* Set the output parameters */
    *pages = ((OE_Page*)data);
    *npages = size / OE_PAGE_SIZE;

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
        free(data);

    return result;
}
