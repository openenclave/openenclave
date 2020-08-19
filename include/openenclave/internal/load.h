// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_LOAD_H
#define _OE_LOAD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/elf.h>
#include "types.h"

OE_EXTERNC_BEGIN

typedef struct _oe_enclave_image oe_enclave_image_t;

typedef struct _oe_sgx_load_context oe_sgx_load_context_t;

typedef struct _oe_sgx_enclave_properties oe_sgx_enclave_properties_t;

typedef struct _oe_elf_segment
{
    /* Size of this segment in memory */
    size_t memsz;

    /* Offset of this segment within file */
    uint64_t offset;

    /* Virtual address of this segment */
    uint64_t vaddr;

    /* Memory protection flags for this segment */
    uint32_t flags;
} oe_elf_segment_t;

typedef struct _oe_enclave_elf_image
{
    elf64_t elf;

    char* image_base;  /* Base of the loaded segment contents */
    size_t image_size; /* Size of all loaded segment contents */

    /* Cached properties of loadable segments for enclave page add */
    oe_elf_segment_t* segments;
    size_t num_segments;

    /* Relocation info for enclave initialization */
    void* reloc_data;
    size_t reloc_size;

    /* Thread-local storage .tdata section */
    uint64_t tdata_rva;
    uint64_t tdata_size;
    uint64_t tdata_align;

    /* Thread-local storage .tbss section */
    uint64_t tbss_size;
    uint64_t tbss_align;

    /*
     * Additional properties used for SGX enclave handling
     */

    /* RVA of the enclave entry point to set in TCS.OENTRY */
    uint64_t entry_rva;

    /* RVA of the .oeinfo section to read oe_sgx_enclave_properties_t
     * during enclave load */
    uint64_t oeinfo_rva;

    /* Offset to write back to the file oe_sgx_enclave_properties_t
     * during signing */
    uint64_t oeinfo_file_pos;

} oe_enclave_elf_image_t;

typedef enum _oe_image_type
{
    OE_IMAGE_TYPE_NONE,
    OE_IMAGE_TYPE_ELF,
} oe_image_type;

struct _oe_enclave_image
{
    oe_image_type type;

    /* Note: this can be part of a union distinguished by type if
     * other enclave binary formats are supported later */
    oe_enclave_elf_image_t elf;

    /* Image type specific callbacks to handle enclave loading */
    oe_result_t (
        *calculate_size)(const oe_enclave_image_t* image, size_t* image_size);

    oe_result_t (*add_pages)(
        oe_enclave_image_t* image,
        oe_sgx_load_context_t* context,
        oe_enclave_t* enclave,
        uint64_t* vaddr);

    oe_result_t (*sgx_patch)(
        oe_enclave_image_t* image,
        oe_sgx_load_context_t* context,
        size_t enclave_size);

    oe_result_t (*sgx_load_enclave_properties)(
        const oe_enclave_image_t* image,
        const char* section_name,
        oe_sgx_enclave_properties_t* properties);

    oe_result_t (*sgx_update_enclave_properties)(
        const oe_enclave_image_t* image,
        const char* section_name,
        const oe_sgx_enclave_properties_t* properties);

    oe_result_t (*unload)(oe_enclave_image_t* image);
};

oe_result_t oe_load_enclave_image(const char* path, oe_enclave_image_t* image);

oe_result_t oe_load_elf_enclave_image(
    const char* path,
    oe_enclave_image_t* image);

oe_result_t oe_unload_enclave_image(oe_enclave_image_t* oeimage);

/**
 * Find the oe_sgx_enclave_properties_t struct within the given section
 *
 * This function attempts to find the **oe_sgx_enclave_properties_t** struct
 * within
 * the specified section of the ELF binary.
 *
 * @param oeimage OE Enclave image
 * @param section_name name of section to search for enclave properties
 * @param properties pointer where enclave properties are copied
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER null parameter
 * @returns OE_FAILURE section was not found
 * @returns OE_NOT_FOUND enclave properties struct not found
 *
 */
oe_result_t oe_sgx_load_enclave_properties(
    const oe_enclave_image_t* oeimage,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties);

/**
 * Update the oe_sgx_enclave_properties_t struct within the given section
 *
 * This function attempts to update the **oe_sgx_enclave_properties_t** struct
 * within the specified section of the ELF binary. If found, the section is
 * updated with the value of the **properties** parameter.
 *
 * @param oeimage OE Enclave image
 * @param section_name name of section to search for enclave properties
 * @param properties new value of enclave properties
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER null parameter
 * @returns OE_FAILURE section was not found
 * @returns OE_NOT_FOUND enclave properties struct not found
 *
 */
oe_result_t oe_sgx_update_enclave_properties(
    const oe_enclave_image_t* oeimage,
    const char* section_name,
    const oe_sgx_enclave_properties_t* properties);

OE_EXTERNC_END

#endif /* _OE_LOAD_H */
