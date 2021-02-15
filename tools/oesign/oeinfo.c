// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oeinfo.h"
#include <openenclave/bits/properties.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include "oe_err.h"

// Load the SGX enclave properties from an enclave's .oeinfo section.
oe_result_t oe_read_oeinfo_sgx(
    const char* path,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_image_t oeimage = {0};

    if (properties)
        memset(properties, 0, sizeof(oe_sgx_enclave_properties_t));

    /* Check parameters */
    if (!path || !properties)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF image */
    OE_CHECK(oe_load_enclave_image(path, &oeimage));

    /* Load the SGX enclave properties */
    OE_CHECK(oe_sgx_load_enclave_properties(
        &oeimage, OE_INFO_SECTION_NAME, properties));

    result = OE_OK;

done:

    if (oeimage.elf.elf.magic == ELF_MAGIC)
        oeimage.unload(&oeimage);

    return result;
}

// Append .signed to the name of the executable to be signed.
static char* _make_signed_lib_name(const char* path)
{
    mem_t buf = MEM_DYNAMIC_INIT;

    mem_append(&buf, path, (size_t)strlen(path));
    mem_append(&buf, ".signed", 8);

    return (char*)mem_steal(&buf);
}

oe_result_t oe_write_oeinfo_sgx(
    const char* path,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_FAILURE;
    oe_enclave_image_t oeimage;
    FILE* os = NULL;

    /* Open ELF file */
    OE_CHECK_ERR(
        oe_load_enclave_image(path, &oeimage),
        "Cannot load ELF file: %s",
        path);

    /* Write the .oeinfo section. */
    OE_CHECK_ERR(
        oe_sgx_update_enclave_properties(
            &oeimage, OE_INFO_SECTION_NAME, properties),
        "Cannot write section: %s",
        OE_INFO_SECTION_NAME);

    /* Write new signed executable */
    {
        char* p = _make_signed_lib_name(path);

        if (!p)
        {
            oe_err("Bad executable name: %s", path);
            goto done;
        }

#ifdef _WIN32
        if (fopen_s(&os, p, "wb") != 0)
#else
        if (!(os = fopen(p, "wb")))
#endif
        {
            oe_err("Failed to open: %s", p);
            goto done;
        }

        if (fwrite(oeimage.elf.elf.data, 1, oeimage.elf.elf.size, os) !=
            oeimage.elf.elf.size)
        {
            oe_err("Failed to write: %s", p);
            goto done;
        }

        fclose(os);
        os = NULL;

        printf("Created %s\n", p);

        free(p);
    }

    result = OE_OK;

done:

    if (os)
        fclose(os);

    oeimage.unload(&oeimage);

    return result;
}
