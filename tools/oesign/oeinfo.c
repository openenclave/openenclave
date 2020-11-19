// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oeinfo.h"
#include <fcntl.h>
#include <openenclave/bits/properties.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include <sys/stat.h>
#include "oe_err.h"

#ifdef __linux__
#define __USE_GNU
#include <unistd.h>
#endif

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
    OE_CHECK(oe_sgx_load_enclave_properties(&oeimage, properties));

    result = OE_OK;

done:
    oe_unload_enclave_image(&oeimage);
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
    int out_fd = 0;
    oe_sgx_enclave_properties_t* oeinfo = NULL;
    size_t oeinfo_offset = 0;

    int in_fd = 0;

    /* Open ELF file */
    OE_CHECK_ERR(
        oe_load_enclave_image(path, &oeimage),
        "Cannot load ELF file: %s",
        path);

    /* Write the .oeinfo section. */
    OE_CHECK_ERR(
        oe_sgx_update_enclave_properties(&oeimage, properties),
        "Cannot write section: %s",
        OE_INFO_SECTION_NAME);

    /* Write new signed executable */
    {
        char* p = _make_signed_lib_name(path);
        OE_ERR_IF(!p, "Bad executable name: %s", path);

#ifdef _WIN32
        OE_ERR_IF(
            !CopyFileEx(path, p, NULL, NULL, NULL, 0),
            "Failed to copy %s to %s",
            path,
            p);

        out_fd = _open(p, _O_WRONLY | _O_BINARY);
        OE_ERR_IF(out_fd <= 0, "Failed to open: %s", p);
#else
        {
            struct stat statbuf;
            ssize_t l = 0;

            in_fd = open(path, O_RDONLY);
            OE_ERR_IF(in_fd <= 0, "Failed to open: %s", path);

            OE_ERR_IF(fstat(in_fd, &statbuf), "Failed to stat: %s", path);

            out_fd = open(p, O_WRONLY | O_CREAT, statbuf.st_mode);
            OE_ERR_IF(out_fd <= 0, "Failed to open: %s", p);

            l = copy_file_range(
                in_fd, NULL, out_fd, NULL, (size_t)statbuf.st_size, 0);
            OE_ERR_IF(
                (l < 0 || l != statbuf.st_size),
                "Failed to copy %s to %s",
                path,
                p);
        }
#endif

        OE_CHECK(oeimage.sgx_get_enclave_properties(
            &oeimage, &oeinfo, &oeinfo_offset));

        ssize_t l = pwrite(
            out_fd, (void*)oeinfo, sizeof(*oeinfo), (off_t)oeinfo_offset);
        OE_ERR_IF(
            (l < 0 || (size_t)l != sizeof(*oeinfo)),
            "Failed to write .oeinfo to file %s",
            p);

        close(out_fd);
        out_fd = 0;

        printf("Created %s\n", p);

        free(p);
    }

    result = OE_OK;

done:
    if (in_fd > 0)
    {
        close(in_fd);
        in_fd = 0;
    }
    if (out_fd > 0)
    {
        close(out_fd);
        out_fd = 0;
    }

    oeimage.unload(&oeimage);

    return result;
}
