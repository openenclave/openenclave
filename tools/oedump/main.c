// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include <stdarg.h>
#include <string.h>

static const char* arg0;

size_t errors = 0;

static bool verbose_opt = false;

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

void DumpEntryPoint(Elf64* elf)
{
    Elf64_Sym sym;
    const char* name;

    if (Elf64_FindDynamicSymbolByAddress(
            elf, Elf64_GetHeader(elf)->e_entry, STT_FUNC, &sym) != 0)
    {
        err("cannot find entry point symbol");
        return;
    }

    if (!(name = Elf64_GetStringFromDynstr(elf, sym.st_name)))
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

void DumpEnclaveProperties(const oe_sgx_enclave_properties_t* props)
{
    const sgx_sigstruct_t* sigstruct;

    printf("=== SGX Enclave Properties:\n");

    printf("product_id=%u\n", props->config.product_id);

    printf("security_version=%u\n", props->config.security_version);

    bool debug = props->config.attributes & OE_SGX_FLAGS_DEBUG;
    printf("debug=%u\n", debug);

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

typedef struct _VisitSymData
{
    const Elf64* elf;
    const Elf64_Shdr* shdr;
    oe_result_t result;
} VisitSymData;

static int _VisitSym(const Elf64_Sym* sym, void* data_)
{
    int rc = -1;
    VisitSymData* data = (VisitSymData*)data_;
    const Elf64_Shdr* shdr = data->shdr;
    const char* name;

    data->result = OE_UNEXPECTED;

    /* Skip symbol if not a function */
    if ((sym->st_info & 0x0F) != STT_FUNC)
    {
        rc = 0;
        goto done;
    }

    /* Skip symbol if not in the ".ecall" section */
    if (sym->st_value < shdr->sh_addr ||
        sym->st_value + sym->st_size > shdr->sh_addr + shdr->sh_size)
    {
        rc = 0;
        goto done;
    }

    /* Skip null names */
    if (!(name = Elf64_GetStringFromDynstr(data->elf, sym->st_name)))
    {
        rc = 0;
        goto done;
    }

    /* Dump the ECALL name */
    printf("%s (%016llx)\n", name, OE_LLX(sym->st_value));

    rc = 0;

done:
    return rc;
}

void DumpECallSection(Elf64* elf)
{
    Elf64_Shdr shdr;

    printf("=== ECALLs:\n");

    /* Find the .ecall section */
    if (Elf64_FindSectionHeader(elf, ".ecall", &shdr) != 0)
    {
        err("missing .ecall section");
        return;
    }

    /* Dump all the ECALLs */
    {
        VisitSymData data;
        data.elf = elf;
        data.shdr = &shdr;

        if (Elf64_VisitSymbols(elf, _VisitSym, &data) != 0)
        {
            err("failed to find ECALLs in .ecall section");
            return;
        }
    }

    printf("\n");
}

void CheckGlobal(Elf64* elf, const char* name)
{
    Elf64_Sym sym;

    if (Elf64_FindDynamicSymbolByName(elf, name, &sym) != 0)
    {
        err("failed to find required symbol: %s\n", name);
        return;
    }

    printf("%s (%016llx)\n", name, OE_LLX(sym.st_value));
}

void CheckGlobals(Elf64* elf)
{
    printf("=== Globals:\n");

    CheckGlobal(elf, "__oe_numPages");
    CheckGlobal(elf, "__oe_virtualBaseAddr");
    CheckGlobal(elf, "__oe_baseRelocPage");
    CheckGlobal(elf, "__oe_numRelocPages");
    CheckGlobal(elf, "__oe_baseECallPage");
    CheckGlobal(elf, "__oe_numECallPages");
    CheckGlobal(elf, "__oe_baseHeapPage");
    CheckGlobal(elf, "__oe_numHeapPages");

    printf("\n");
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = 1;
    Elf64 elf;
    oe_sgx_enclave_properties_t props;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", arg0);
        goto done;
    }

    /* Load the ELF-64 object */
    if (Elf64_Load(argv[1], &elf) != 0)
    {
        fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[1]);
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
    DumpEntryPoint(&elf);

    /* Dump the signature section */
    DumpEnclaveProperties(&props);

    /* Dump the ECALL section */
    DumpECallSection(&elf);

    /* Check globals */
    CheckGlobals(&elf);

    if (errors)
    {
        fprintf(stderr, "*** Found %zu errors\n", errors);
        goto done;
    }

    ret = 0;

done:
    Elf64_Unload(&elf);
    return ret;
}
