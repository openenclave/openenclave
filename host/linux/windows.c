// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "windows.h"
#include <malloc.h>
#include <openenclave/internal/defs.h>

HMODULE LoadLibraryExA(LPCSTR path, HANDLE file, DWORD flags)
{
    HMODULE ret = NULL;
    FILE* is = NULL;
    void* data = NULL;
    struct stat st;

    if (!path || file || flags != LOAD_LIBRARY_AS_IMAGE_RESOURCE)
        goto done;

    /* Get the size of the PE image file. */
    if (stat(path, &st) != 0)
        goto done;

    /* Allocate memory to hold the image (align on a page boundary). */
    if (!(data = memalign(OE_PAGE_SIZE, (size_t)st.st_size)))
        goto done;

    /* Open the PE file. */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read the image into memory */
    if (fread(data, 1, (size_t)st.st_size, is) != (size_t)st.st_size)
        goto done;

    /* Check whether the header magic number is correct. */
    {
        const IMAGE_DOS_HEADER* header = (const IMAGE_DOS_HEADER*)data;

        if (header->e_magic != IMAGE_DOS_SIGNATURE)
            goto done;
    }

    ret = (HMODULE)data;
    data = NULL;

done:

    if (is)
        fclose(is);

    if (data)
        free(is);

    return (HMODULE)ret;
}

BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect)
{
    OE_UNUSED(lpAddress);
    OE_UNUSED(dwSize);
    OE_UNUSED(flNewProtect);
    OE_UNUSED(lpflOldProtect);
    /* Nothing to do. */
    return true;
}

BOOL FreeLibrary(HMODULE module)
{
    if (module)
        free(module);

    return true;
}
