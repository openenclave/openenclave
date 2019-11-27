// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/internal/elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* arg0;

const size_t HASH_SIZE = 32;

static bool valid_symbol_name(const char* name)
{
    bool ret = false;
    const char* p = name;

    if (*p != '_' && !isalpha(*p))
        goto done;

    p++;

    while (*p == '_' || isalnum(*p))
        p++;

    if (*p != '\0')
        goto done;

    ret = true;

done:
    return ret;
}

static bool valid_symbol_value(const char* value)
{
    bool ret = false;
    const char* p = value;

    while (isxdigit(*p))
        p++;

    if (*p != '\0')
        goto done;

    if (p - value != 64)
        goto done;

    ret = true;

done:
    return ret;
}

void dump_symbol(const uint8_t* symbol)
{
    for (size_t i = 0; i < HASH_SIZE; i++)
        printf("%02x", symbol[i]);

    printf("\n");
}

static uint64_t find_file_offset(elf64_t* elf, uint64_t vaddr)
{
    elf64_ehdr_t* eh = (elf64_ehdr_t*)elf->data;
    elf64_phdr_t* ph = (elf64_phdr_t*)((uint8_t*)elf->data + eh->e_phoff);
    size_t i;

    /* Search for the segment that contains this virtual address. */
    for (i = 0; i < eh->e_phnum; i++)
    {
        if (vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_memsz)
        {
            size_t vaddr_offset = vaddr - ph->p_vaddr;

            /* Calculate the offset within the file. */
            size_t file_offset = ph->p_offset + vaddr_offset;

            if (file_offset >= elf->size)
                return (uint64_t)-1;

            return file_offset;
        }

        ph++;
    }

    return (uint64_t)-1;
}

int ascii_to_hash(const char* sha256_value, uint8_t hash[HASH_SIZE])
{
    const char* p = sha256_value;

    memset(hash, 0, HASH_SIZE);

    if (!valid_symbol_value(sha256_value))
        return -1;

    for (size_t i = 0; i < HASH_SIZE; i++)
    {
        unsigned int byte;
        sscanf(p, "%02x", &byte);
        hash[i] = (uint8_t)byte;
        p += 2;
    }

    return 0;
}

int write_file(const char* path, const void* data, size_t size)
{
    FILE* os;

    if (!(os = fopen(path, "wb")))
        return -1;

    if (fwrite(data, 1, size, os) != size)
        return -1;

    fclose(os);

    return 0;
}

static const char _usage[] =
    "\n"
    "Usage: %s ELF-IMAGE SHA256-SYMBOL [SHA256-VALUE]\n"
    "\n"
    "For the given ELF-IMAGE, this tool sets the value of the SHA256-SYMBOL\n"
    "to SHA256-VALUE. The author of the ELF-IMAGE is responsible for ensuring\n"
    "that the image contains a symbol with that name, whose size is exactly\n"
    "32 bytes (binary format). SHA256-VALUE is a sequence of 64 hex\n"
    "characters. For example:\n"
    "\n"
    "    f7ce30b1aeef4f2e9d1cc346c291c15b0e99ce9a20d34cecaca04d36f68f1232\n"
    "\n"
    "If successful, the ELF-IMAGE file is updated in place.\n"
    "\n";

int main(int argc, const char* argv[])
{
    const char* elf_image;
    const char* sha256_symbol;
    const char* sha256_value = NULL;
    elf64_t elf;
    bool loaded = false;
    elf64_sym_t sym;
    uint8_t* symbol_address;
    size_t file_offset;
    uint8_t hash[HASH_SIZE];

    arg0 = argv[0];

    int ret = 1;

    /* Check and collect arguments. */
    {
        if (argc != 3 && argc != 4)
        {
            fprintf(stderr, _usage, argv[0]);
            goto done;
        }

        elf_image = argv[1];
        sha256_symbol = argv[2];

        if (argc == 4)
            sha256_value = argv[3];
    }

    /* Disable logging. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    /* Check that the symbol name is valid. */
    if (!valid_symbol_name(sha256_symbol))
    {
        fprintf(stderr, "%s: invalid symbol name: %s\n", arg0, sha256_symbol);
        goto done;
    }

    /* Check that the symbol value is valid. */
    if (sha256_value && !valid_symbol_value(sha256_value))
    {
        fprintf(stderr, "%s: invalid symbol value: %s\n", arg0, sha256_value);
        goto done;
    }

    /* Load the ELF-64 object */
    {
        if (elf64_load(elf_image, &elf) != 0)
        {
            fprintf(stderr, "%s: failed to load %s\n", arg0, elf_image);
            goto done;
        }

        loaded = true;
    }

    /* Find the symbol within the ELF image. */
    if (elf64_find_symbol_by_name(&elf, sha256_symbol, &sym) != 0)
    {
        fprintf(stderr, "%s: cannot find symbol: %s\n", arg0, sha256_symbol);
        goto done;
    }

    /* The size of the symbol must be 64-bytes. */
    if (sym.st_size != HASH_SIZE)
    {
        fprintf(
            stderr,
            "%s: the size of the symbol should be %zu bytes: %s\n",
            arg0,
            HASH_SIZE,
            sha256_symbol);
        goto done;
    }

    /* Find the offset within the ELF file of this symbol. */
    if ((file_offset = find_file_offset(&elf, sym.st_value)) == (uint64_t)-1)
    {
        fprintf(stderr, "%s: cannot resolve symbol.\n", arg0);
        goto done;
    }

    /* Make sure the entire symbol falls within the file image. */
    if (file_offset + HASH_SIZE > elf.size)
    {
        fprintf(stderr, "%s: unexpected error.\n", arg0);
        goto done;
    }

    /* Get the address of the symbol. */
    symbol_address = (uint8_t*)elf.data + file_offset;

    /* Update the symbol value. */
    if (argc == 3)
    {
        dump_symbol(symbol_address);
    }
    else
    {
        /* Convert the ASCII hex string to a hash. */
        if (ascii_to_hash(sha256_value, hash) != 0)
        {
            fprintf(stderr, "%s: failed to convert value to binary.\n", arg0);
            goto done;
        }

        /* Set the symbol value. */
        memcpy(symbol_address, hash, sizeof(hash));

        /* Rewrite the file. */
        if (write_file(elf_image, elf.data, elf.size) != 0)
        {
            fprintf(stderr, "%s: failed to write: %s\n", arg0, elf_image);
            goto done;
        }
    }

    ret = 0;

done:

    if (loaded)
        elf64_unload(&elf);

    return ret;
}
