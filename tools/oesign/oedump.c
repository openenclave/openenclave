// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/types.h>
#include <stdio.h>
#include <string.h>
#include "oe_err.h"
#include "oeinfo.h"

static bool verbose_opt = false;

static void _dump_entry_point(const elf64_t* elf)
{
    elf64_sym_t sym;
    const char* name = NULL;

    if (elf64_find_dynamic_symbol_by_address(
            elf, elf64_get_header(elf)->e_entry, STT_FUNC, &sym) != 0)
    {
        oe_err("Cannot find entry point symbol");
        return;
    }

    name = elf64_get_string_from_dynstr(elf, sym.st_name);
    if (!name)
    {
        oe_err("Cannot resolve entry point name");
        return;
    }

    if (strcmp(name, "_start") != 0)
    {
        oe_err("Invalid entry point name: %s", name);
        return;
    }

    printf("=== Entry point: \n");
    printf("name=%s\n", name);
    printf("address=%#016llx\n", OE_LLX(sym.st_value));
    printf("\n");
}

/* The provided public_key_modulus must be in little-endian
 * format for this function, which is the format used in the
 * sgx_sigstruct_t.modulus field.
 */
static void _dump_mrsigner(
    const uint8_t* public_key_modulus,
    size_t public_key_modulus_size)
{
    OE_SHA256 mrsigner = {0};

    /* Check if modulus value is not set */
    size_t i = 0;
    while (i < public_key_modulus_size && public_key_modulus[i] == 0)
        i++;

    if (public_key_modulus_size > i)
        oe_sha256(public_key_modulus, public_key_modulus_size, &mrsigner);

    oe_hex_dump(mrsigner.buf, sizeof(mrsigner.buf));
}

static void _dump_enclave_properties(const oe_sgx_enclave_properties_t* props)
{
    const sgx_sigstruct_t* sigstruct;

    printf("=== SGX Enclave Properties:\n");

    printf("product_id=%u\n", props->config.product_id);

    printf("security_version=%u\n", props->config.security_version);

    bool debug = props->config.attributes & OE_SGX_FLAGS_DEBUG;
    printf("debug=%u\n", debug);

    printf("xfrm=%#016llx\n", OE_LLX(props->config.xfrm));

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

    printf("mrsigner=");
    _dump_mrsigner(sigstruct->modulus, sizeof(sigstruct->modulus));

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
        oe_err("Failed to load %s as ELF64", enc_bin);
        goto done;
    }

    /* Load the SGX enclave properties */
    if (oe_read_oeinfo_sgx(enc_bin, &props) != OE_OK)
    {
        oe_err(
            "Failed to load SGX enclave properties from %s section",
            OE_INFO_SECTION_NAME);
    }

    printf("\n");

    /* Dump the entry point */
    _dump_entry_point(&elf);

    /* Dump the signature section */
    _dump_enclave_properties(&props);

    oe_print_err_count();
    ret = 0;

done:
    elf64_unload(&elf);
    return ret;
}
