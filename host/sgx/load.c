// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <stdio.h>
#include "../fopen.h"
#include "enclave.h"

#if defined(_WIN32)
#include <windows.h>
#endif

static oe_result_t _get_image_type(const char* path, oe_image_type* type)
{
    oe_result_t result = OE_UNEXPECTED;
    FILE* is = NULL;

    /* Check whether this is an ELF image */
    {
        elf64_ehdr_t header;

        if (oe_fopen(&is, path, "rb") != 0)
            OE_RAISE(OE_NOT_FOUND);

        if (fread(&header, 1, sizeof(header), is) != sizeof(header))
            OE_RAISE(OE_FAILURE);

        if (elf64_test_header(&header) == 0)
        {
            *type = OE_IMAGE_TYPE_ELF;
            OE_RAISE(OE_OK);
        }

        fclose(is);
        is = NULL;
    }

    *type = OE_IMAGE_TYPE_NONE;
    result = OE_OK;

done:
    if (is)
        fclose(is);

    return result;
}

oe_result_t oe_load_enclave_image(const char* path, oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_image_type type;
    char* path1 = NULL;
    const char* path2 = NULL;

    if (!path || !image)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Split the path into two paths: path1 and path2 */
    {
        char* p;

        if (!(path1 = strdup(path)))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if ((p = strchr(path1, ':')))
        {
            *p = '\0';
            path2 = p + 1;
        }
    }

    OE_CHECK(_get_image_type(path1, &type));

    if (path2)
        OE_CHECK(_get_image_type(path2, &type));

    switch (type)
    {
        case OE_IMAGE_TYPE_NONE:
            OE_RAISE_MSG(OE_FAILURE, "Bad image type:OE_IMAGE_TYPE_NONE", NULL);
        case OE_IMAGE_TYPE_ELF:
            OE_RAISE(oe_load_elf_enclave_image(path, image));
    }
done:

    if (path1)
        free(path1);

    return result;
}

oe_result_t oe_unload_enclave_image(oe_enclave_image_t* oeimage)
{
    if (!oeimage || !oeimage->unload)
        return OE_INVALID_PARAMETER;

    return oeimage->unload(oeimage);
}

oe_result_t oe_sgx_load_enclave_properties(
    const oe_enclave_image_t* oeimage,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties)
{
    if (!oeimage || !oeimage->sgx_load_enclave_properties)
        return OE_INVALID_PARAMETER;

    return oeimage->sgx_load_enclave_properties(
        oeimage, section_name, properties);
}

oe_result_t oe_sgx_update_enclave_properties(
    const oe_enclave_image_t* oeimage,
    const char* section_name,
    const oe_sgx_enclave_properties_t* properties)
{
    if (!oeimage || !oeimage->sgx_update_enclave_properties)
        return OE_INVALID_PARAMETER;

    return oeimage->sgx_update_enclave_properties(
        oeimage, section_name, properties);
}
