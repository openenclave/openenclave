// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <inttypes.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/utils.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

size_t errors = 0;

static bool verbose_opt = false;

/* Find enclave property struct within an .oeinfo section */
static oe_result_t _find_enclave_properties(
    uint8_t* section_data,
    size_t section_size,
    oe_enclave_type_t enclave_type,
    size_t struct_size,
    oe_sgx_enclave_properties_t** enclave_properties)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* ptr = section_data;
    size_t bytes_remaining = section_size;

    *enclave_properties = NULL;

    /* While there are more enclave property structures */
    while (bytes_remaining >= struct_size)
    {
        oe_sgx_enclave_properties_t* p = (oe_sgx_enclave_properties_t*)ptr;

        if (p->header.enclave_type == enclave_type)
        {
            if (p->header.size != struct_size)
            {
                result = OE_FAILURE;
                goto done;
            }

            /* Found it! */
            *enclave_properties = p;
            break;
        }

        /* If size of structure extends beyond end of section */
        if (p->header.size > bytes_remaining)
            break;

        ptr += p->header.size;
        bytes_remaining -= p->header.size;
    }

    if (*enclave_properties == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_load_properties(
    const elf64_t* elf,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* section_data;
    size_t section_size;

    if (properties)
        memset(properties, 0, sizeof(*properties));

    /* Check for null parameter */
    if (!elf || !section_name || !properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Get pointer to and size of the given section */
    if (elf64_find_section(elf, section_name, &section_data, &section_size) !=
        0)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    /* Find SGX enclave property struct */
    {
        oe_sgx_enclave_properties_t* enclave_properties;

        if ((result = _find_enclave_properties(
                 section_data,
                 section_size,
                 OE_ENCLAVE_TYPE_SGX,
                 sizeof(oe_sgx_enclave_properties_t),
                 &enclave_properties)) != OE_OK)
        {
            result = OE_NOT_FOUND;
            goto done;
        }

        OE_CHECK(oe_memcpy_s(
            properties,
            sizeof(*properties),
            enclave_properties,
            sizeof(*enclave_properties)));
    }

    result = OE_OK;

done:
    return result;
}

OE_PRINTF_FORMAT(1, 2)
void err(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "*** Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    errors++;
}

void dump_entry_point(elf64_t* elf)
{
    elf64_sym_t sym;
    const char* name;

    if (elf64_find_dynamic_symbol_by_address(
            elf, elf64_get_header(elf)->e_entry, STT_FUNC, &sym) != 0)
    {
        err("cannot find entry point symbol");
        return;
    }

    if (!(name = elf64_get_string_from_dynstr(elf, sym.st_name)))
    {
        err("cannot resolve entry point name");
        return;
    }

    if (strcmp(name, "_start") != 0)
    {
        err("invalid entry point name: %s", name);
        return;
    }

    printf("=== Entry point: \n");
    printf("name=%s\n", name);
    printf("address=%016llx\n", OE_LLX(sym.st_value));
    printf("\n");
}

void dump_enclave_properties(const oe_sgx_enclave_properties_t* props)
{
    const sgx_sigstruct_t* sigstruct;

    printf("=== SGX Enclave Properties:\n");

    printf("product_id=%u\n", props->config.product_id);

    printf("security_version=%u\n", props->config.security_version);

    bool debug = props->config.attributes & OE_SGX_FLAGS_DEBUG;
    printf("debug=%u\n", debug);

    printf("xfrm=%" PRIx64 "\n", props->config.xfrm);

    printf(
        "num_heap_pages=%llu\n",
        OE_LLU(props->header.size_settings.num_heap_pages));

    printf(
        "num_stack_pages=%llu\n",
        OE_LLU(props->header.size_settings.num_stack_pages));

    printf("num_tcs=%llu\n", OE_LLU(props->header.size_settings.num_tcs));

    sigstruct = (const sgx_sigstruct_t*)props->sigstruct;

    printf("mrenclave=");
    oe_hex_dump(sigstruct->enclavehash, sizeof(sigstruct->enclavehash));

    printf("signature=");
    oe_hex_dump(sigstruct->signature, sizeof(sigstruct->signature));

    printf("\n");

    if (verbose_opt)
        __sgx_dump_sigstruct(sigstruct);
}

int oedump(const char* enc_bin)
{
    int ret = 1;
    elf64_t elf;
    oe_sgx_enclave_properties_t props;

    /* Load the ELF-64 object */
    if (elf64_load(enc_bin, &elf) != 0)
    {
        fprintf(stderr, "failed to load %s\n", enc_bin);
        goto done;
    }

    /* Load the SGX enclave properties */
    if (oe_sgx_load_properties(&elf, OE_INFO_SECTION_NAME, &props) != OE_OK)
    {
        err("failed to load SGX enclave properties from %s section",
            OE_INFO_SECTION_NAME);
    }

    printf("\n");

    /* Dump the entry point */
    dump_entry_point(&elf);

    /* Dump the signature section */
    dump_enclave_properties(&props);

    if (errors)
    {
        fprintf(stderr, "*** Found %zu errors\n", errors);
        goto done;
    }

    ret = 0;

done:
    elf64_unload(&elf);
    return ret;
}
