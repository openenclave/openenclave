// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LOAD_H
#define _OE_LOAD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include "types.h"

#if defined(__linux__)
#include <openenclave/internal/elf.h>
#endif

OE_EXTERNC_BEGIN

#if defined(__linux__)

#define OE_MAX_SEGMENTS 16

#define OE_SEGMENT_FLAG_READ 1
#define OE_SEGMENT_FLAG_WRITE 2
#define OE_SEGMENT_FLAG_EXEC 4

typedef struct _oe_segment
{
    /* Pointer to segment from ELF file */
    void* filedata;

    /* Size of this segment in the ELF file */
    size_t filesz;

    /* Size of this segment in memory */
    size_t memsz;

    /* Offset of this segment within file */
    uint64_t offset;

    /* Virtual address of this segment */
    uint64_t vaddr;

    /* Memory protection flags for this segment */
    uint32_t flags;
} oe_segment_t;

#endif // defined(__linux__)

typedef struct _oe_enclave_image_t
{
    char* image_base;       /* base of image */
    size_t image_size;      /* rva of entry_rva point */
    uint64_t entry_rva;     /* rva of .text section */
    uint64_t text_rva;      /* rva and file position of .oeinfo section */

    /* N.B. file position is needed when we need to write back  */
    /*      oe_sgx_enclave_properties_t during signing          */
    uint64_t oeinfo_rva;
    uint64_t oeinfo_file_pos;

    /* rva/size of .ecall section */
    uint64_t ecall_rva;
    uint64_t ecall_section_size;

    /* size of relocation */
    size_t reloc_size;

#if defined(__linux__)

    elf64_t elf;
    oe_segment_t *segments;
    size_t num_segments;
    void* reloc_data;

#elif defined(_WIN32)

    void *module;
    void *nt_header;
    uint64_t reloc_rva;

#else

#error("unsupported");

#endif

} oe_enclave_image_t;

oe_result_t _oe_load_enclave_image(
    const char* path,
    oe_enclave_image_t* oeimage);

oe_result_t _oe_unload_enclave_image(
    oe_enclave_image_t* oeimage);

OE_EXTERNC_END

#endif /* _OE_LOAD_H */
