// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include "split_t.h"

#define printf oe_host_printf

#if 0
typedef struct
{
    unsigned char e_ident[16];
    elf64_half_t e_type;
    elf64_half_t e_machine;
    elf64_word_t e_version;
    elf64_addr_t e_entry;     /* entry point virtual address */
    elf64_off_t e_phoff;      /* program header table offset */
    elf64_off_t e_shoff;      /* (40) section header table offset */
    elf64_word_t e_flags;     /* process-specific flags */
    elf64_half_t e_ehsize;    /* ELF header size */
    elf64_half_t e_phentsize; /* Program header table entry size */
    elf64_half_t e_phnum;     /* Number of program header table entries */
    elf64_half_t e_shentsize; /* Section header size */
    elf64_half_t e_shnum;     /* Number of section headers */
    elf64_half_t e_shstrndx;  /* Index of the string-table section header */
} elf64_ehdr_t;
#endif

void _dump(const uint8_t* p, size_t n)
{
    while (n--)
    {
        uint8_t x = *p++;

        if (x >= ' ' && x <= '~')
            printf("%c ", x);
        else
            printf("%02X ", x);
    }
    printf("\n");
}

static void callback(const char* msg)
{
    oe_host_printf("callback()\n");
    oe_host_printf("msg=%p\n", msg);
    oe_host_printf("msg=%s\n", msg);
    (void)msg;
}

int split_ecall(void)
{
    const void* entry = __oe_get_isolated_image_entry_point();
    typedef void (*start_t)(void (*callback)(const char* msg));

    oe_assert(entry);

    start_t start = (start_t)entry;

    printf("before\n");
    (*start)(callback);
    printf("after\n");

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
