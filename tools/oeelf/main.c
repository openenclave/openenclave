#include <assert.h>
#include <openenclave/bits/elf.h>
#include <stdio.h>
#include <stdlib.h>

/*
**==============================================================================
**
** To use this for loading an enclave, check these:
**     header.e_type=ET_DYN
**     iheader.e_machine=EM_X86_64
**
**==============================================================================
*/

int main(int argc, const char* argv[])
{
    int status = 1;
    FILE* is = NULL;
    Elf64 elf;

    /* Check argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
        return 1;
    }

    assert(sizeof(Elf64_Addr) == 8);
    assert(sizeof(Elf64_Off) == 8);
    assert(sizeof(Elf64_Half) == 2);
    assert(sizeof(Elf64_Word) == 4);
    assert(sizeof(Elf64_Sword) == 4);
    assert(sizeof(Elf64_Xword) == 8);
    assert(sizeof(Elf64_Sxword) == 8);

#if 0
printf("%zu\n", offsetof(Elf64_Ehdr, e_shoff));
printf("%zu\n", offsetof(Elf64_Ehdr, e_shnum));
exit(0);
#endif

    /* Load the ELF-64 object */
    if (Elf64_Load(argv[1], &elf) != 0)
    {
        fprintf(stderr, "%s: failed to load %s\n", argv[0], argv[1]);
        goto done;
    }

    Elf64_Dump(&elf);
    Elf64_DumpSymbols(&elf);
    Elf64_DumpSections(&elf);
    Elf64_DumpSectionNames(&elf);
    Elf64_DumpStrings(&elf);

    /* Find the entry point symbol */
    const char* entry;
    {
        Elf64_Sym sym;

        if (Elf64_FindSymbolByAddress(&elf, elf.ehdr->e_entry, STT_FUNC, &sym) != 0)
        {
            fprintf(stderr, "%s: cannot find entry point symbol\n", argv[0]);
            goto done;
        }

        if (!(entry = Elf64_GetStringFromStrtab(&elf, sym.st_name)))
        {
            fprintf(stderr, "%s: cannot resolve entry point name\n", argv[0]);
            goto done;
        }

        printf("=== entry point: {%s}\n\n", entry);
    }

    /* Find a symbol by name */
    {
        Elf64_Sym sym;

        if (Elf64_FindSymbolByName(&elf, entry, &sym) != 0)
        {
            fprintf(stderr, "%s: failed to find entry point: %s\n", argv[0], entry);
            goto done;
        }

        Elf64_DumpSymbol(&elf, &sym);
    }

#if 0
    {
        /* Add a new section */
        {
            const char secdata[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
            size_t secsize = sizeof(secdata);

            if (Elf64_AddSection(
                &elf, ".mysec", SHT_PROGBITS, secdata, secsize) != 0)
            {
                fprintf(stderr, "%s: failed to add section\n", argv[0]);
                goto done;
            }
        }

        /* Add a new section */
        {
            const char secdata[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
            size_t secsize = sizeof(secdata);

            if (Elf64_AddSection(
                &elf, ".mysec2", SHT_PROGBITS, secdata, secsize) != 0)
            {
                fprintf(stderr, "%s: failed to add section\n", argv[0]);
                goto done;
            }
        }

        Elf64_Dump(&elf);
        Elf64_DumpSymbols(&elf);
        Elf64_DumpSections(&elf);
        Elf64_DumpSectionNames(&elf);
    }
#endif

    /* Unload tghe ELF-64 object */
    if (Elf64_Unload(&elf) != 0)
    {
        fprintf(stderr, "%s: failed to unload\n", argv[0]);
        goto done;
    }

    status = 0;

done:

    if (is)
        fclose(is);

    return status;
}
