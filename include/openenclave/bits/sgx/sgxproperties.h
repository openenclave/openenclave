// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file sgxproperties.h
 *
 * This file defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled
 * into an enclave binary using the OE_SET_ENCLAVE_SGX macro.
 * These properties can be overwritten at sign time by the oesign tool.
 */

#ifndef _OE_BITS_SGX_SGXPROPERTIES_H
#define _OE_BITS_SGX_SGXPROPERTIES_H

/* Image information */
typedef struct _oe_sgx_enclave_image_info_t
{
    uint64_t oeinfo_rva;
    uint64_t oeinfo_size;
    uint64_t reloc_rva;
    uint64_t reloc_size;
    uint64_t ecall_rva;
    uint64_t ecall_size;
    uint64_t heap_rva; /* heap size is in header.sizesettings */
    uint64_t enclave_size;
} oe_sgx_enclave_image_info_t;

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

// oe_sgx_enclave_properties_t SGX enclave properties derived type
#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define OE_SGX_SIGSTRUCT_SIZE 1808

typedef struct oe_sgx_enclave_config_t
{
    uint16_t product_id;
    uint16_t security_version;

    /* Padding to make packed and unpacked size the same */
    uint32_t padding;

    /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT) */
    uint64_t attributes;
} oe_sgx_enclave_config_t;

/* Extends oe_enclave_properties_header_t base type */
typedef struct _oe_sgx_enclave_properties
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (48) */
    oe_sgx_enclave_image_info_t image_info;

    /* (112)  */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];

    /* (1920) end-marker to make sure 0-filled signstruct doesn't get omitted */
    uint64_t end_marker;
} oe_sgx_enclave_properties_t;

#define OE_INFO_SECTION_BEGIN \
    OE_EXTERNC __attribute__((section(OE_INFO_SECTION_NAME)))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(ALLOW_DEBUG) \
    (OE_SGX_FLAGS_MODE64BIT | (ALLOW_DEBUG ? OE_SGX_FLAGS_DEBUG : 0))

// This macro initializes and injects an oe_sgx_enclave_properties_t struct
// into the .oeinfo section.

/**
 * Defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary. These properties can be overwritten at sign time by
 * the oesign tool.
 *
 * @param PRODUCT_ID ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param SECURITY_VERSION ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param ALLOW_DEBUG If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param HEAP_PAGE_COUNT Number of heap pages to allocate in the enclave
 * @param STACK_PAGE_COUNT Number of stack pages per thread to reserve in
 * the enclave
 * @param TCS_COUNT Number of concurrent threads in an enclave to support
 */
// Note: disable clang-format since it badly misformats this macro
// clang-format off

#define OE_SET_ENCLAVE_SGX(                                               \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    ALLOW_DEBUG,                                                          \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)                                                            \
    OE_INFO_SECTION_BEGIN                                                 \
    volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx = \
    {                                                                     \
        .header =                                                         \
        {                                                                 \
            .size = sizeof(oe_sgx_enclave_properties_t),                  \
            .enclave_type = OE_ENCLAVE_TYPE_SGX,                          \
            .size_settings =                                              \
            {                                                             \
                .num_heap_pages = HEAP_PAGE_COUNT,                        \
                .num_stack_pages = STACK_PAGE_COUNT,                      \
                .num_tcs = TCS_COUNT                                      \
            }                                                             \
        },                                                                \
        .config =                                                         \
        {                                                                 \
            .product_id = PRODUCT_ID,                                     \
            .security_version = SECURITY_VERSION,                         \
            .padding = 0,                                                 \
            .attributes = OE_MAKE_ATTRIBUTES(ALLOW_DEBUG)                 \
        },                                                                \
        .image_info =                                                     \
        {                                                                 \
            0                                                             \
        },                                                                \
        .sigstruct =                                                      \
        {                                                                 \
            0                                                             \
        },                                                                \
        .end_marker = 0xecececececececec,                                 \
    };                                                                    \
    OE_INFO_SECTION_END

// clang-format on

#endif /* _OE_BITS_SGX_SGXPROPERTIES_H */
