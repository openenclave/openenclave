// Copyright (c) Open Enclave SDK contributors.
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
    uint64_t heap_rva; /* heap size is in header.sizesettings */
    uint64_t enclave_size;
} oe_sgx_enclave_image_info_t;

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

// oe_sgx_enclave_properties_t SGX enclave properties derived type
#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define OE_SGX_FLAGS_KSS 0x0000000000000080ULL
#define OE_SGX_SIGSTRUCT_SIZE 1808

typedef struct _oe_sgx_enclave_flags_t
{
    uint32_t capture_pf_gp_exceptions : 1;
    uint32_t create_zero_base_enclave : 1;
    uint32_t reserved : 30;
} oe_sgx_enclave_flags_t;

typedef struct oe_sgx_enclave_config_t
{
    uint16_t product_id;
    uint16_t security_version;

    oe_sgx_enclave_flags_t flags;

    uint8_t family_id[16];
    uint8_t extended_product_id[16];
    /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT | OE_SGX_FLAGS_KSS) */
    uint64_t attributes;

    /* XSave Feature Request Mask */
    uint64_t xfrm;

    /* Enclave start address. Currently valid only for 0-base enclave */
    uint64_t start_address;
} oe_sgx_enclave_config_t;

/* Extends oe_enclave_properties_header_t base type */
typedef struct _oe_sgx_enclave_properties
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (96) */
    oe_sgx_enclave_image_info_t image_info;

    /* (144)  */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];

    /* (1960) end-marker to make sure 0-filled signstruct doesn't get omitted */
    uint64_t end_marker;
} oe_sgx_enclave_properties_t;

#define OE_INFO_SECTION_BEGIN \
    OE_EXTERNC __attribute__((section(OE_INFO_SECTION_NAME)))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(ALLOW_DEBUG, REQUIRE_KSS)                   \
    (OE_SGX_FLAGS_MODE64BIT | (ALLOW_DEBUG ? OE_SGX_FLAGS_DEBUG : 0) | \
     (REQUIRE_KSS ? OE_SGX_FLAGS_KSS : 0))

#define OE_ADDRESS_ZERO 0x0

/*
 * ex_feature constants
 * These constants will have to be updated as new ex_features are
 * introduced in sgx.
 */
#define OE_SGX_ENCLAVE_CREATE_MAX_EX_FEATURES_COUNT 32
#define OE_SGX_ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX 0
// Reserve Bit 0 for el_range feature
#define OE_SGX_ENCLAVE_CREATE_EX_EL_RANGE \
    (1 << OE_SGX_ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX)

// This macro initializes and injects an oe_sgx_enclave_properties_t struct
// into the .oeinfo section.

/**
 * Defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary. These properties can be overwritten at sign time by
 * the oesign tool.
 *
 * @param[in] PRODUCT_ID ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param[in] SECURITY_VERSION ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param[in] EXTENDED_PRODUCT_ID ISV assigned Extended Product ID
 * (ISVEXTPRODID) to use in the enclave signature
 * @param[in] FAMILY_ID ISV assigned Product Family ID (ISVFAMILYID)
 * to use in the enclave signature
 * @param[in] ALLOW_DEBUG If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param[in] REQUIRE_KSS If true, allows the enclave to be created with
 * KSS properties
 * @param[in] CAPTURE_PF_GP_EXCEPTIONS If true, allows the enclave to capture
 * #PF and #GP exceptions if the CPU supports the feature. The setting is
 * ignored otherwise
 * @param[in] CREATE_ZERO_BASE_ENCLAVE If true, allows enclave to be created
 * with a base address of 0x0. Else, the usual enclave creation logic is
 * followed. Currently available only for SGX on linux. On windows,
 * the input should be false.
 * @param[in] ENCLAVE_START_ADDRESS If CREATE_ZERO_BASE_ENCLAVE is set, the
 * enclave image start address. Must be higher than value in
 * /proc/sys/vm/mmap_min_addr. Currently available only for SGX on linux. On
 * windows, the input should be 0.
 * @param[in] HEAP_PAGE_COUNT Number of heap pages to allocate in the enclave
 * @param[in] STACK_PAGE_COUNT Number of stack pages per thread to reserve in
 * the enclave
 * @param[in] TCS_COUNT Number of concurrent threads in an enclave to support
 */
// Note: disable clang-format since it badly misformats this macro
// clang-format off

#define _OE_SET_ENCLAVE_SGX_IMPL(                                         \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    EXTENDED_PRODUCT_ID,                                                  \
    FAMILY_ID,                                                            \
    ALLOW_DEBUG,                                                          \
    REQUIRE_KSS,                                                          \
    CAPTURE_PF_GP_EXCEPTIONS,                                             \
    CREATE_ZERO_BASE_ENCLAVE,                                             \
    ENCLAVE_START_ADDRESS,                                                \
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
            .flags =                                                      \
            {                                                             \
                .capture_pf_gp_exceptions = CAPTURE_PF_GP_EXCEPTIONS,     \
                .create_zero_base_enclave = CREATE_ZERO_BASE_ENCLAVE,     \
                .reserved = 0                                             \
            },                                                            \
            .family_id = FAMILY_ID,                                       \
            .extended_product_id = EXTENDED_PRODUCT_ID,                   \
            .attributes = OE_MAKE_ATTRIBUTES(ALLOW_DEBUG, REQUIRE_KSS),   \
            .start_address =                                              \
                CREATE_ZERO_BASE_ENCLAVE ? ENCLAVE_START_ADDRESS : 0,     \
        },                                                                \
        .image_info =                                                     \
        {                                                                 \
            0, 0, 0, 0, 0, 0                                              \
        },                                                                \
        .sigstruct =                                                      \
        {                                                                 \
            0                                                             \
        },                                                                \
        .end_marker = 0xecececececececec,                                 \
    };                                                                    \
    OE_INFO_SECTION_END

/**
 * Defines the SGX properties for an enclave without KSS properties
 *
 * Maps to _OE_SET_ENCLAVE_SGX_IMPL with zero arrays for FAMILY_ID
 * and EXTENDED_PRODUCT_ID and false for REQUIRE_KSS
 * @param[in] PRODUCT_ID ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param[in] SECURITY_VERSION ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param[in] ALLOW_DEBUG If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param[in] HEAP_PAGE_COUNT Number of heap pages to allocate in the enclave
 * @param[in] STACK_PAGE_COUNT Number of stack pages per thread to reserve in
 * the enclave
 * @param[in] TCS_COUNT Number of concurrent threads in an enclave to support
 */

#define OE_SET_ENCLAVE_SGX(                                               \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    ALLOW_DEBUG,                                                          \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)                                                            \
 _OE_SET_ENCLAVE_SGX_IMPL(                                                \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    {0},                                                                  \
    {0},                                                                  \
    ALLOW_DEBUG,                                                          \
    false,                                                                \
    0,                                                                    \
    false,                                                                \
    0,                                                                    \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)

/**
 * Defines the SGX2 properties for an enclave
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary. These properties can be overwritten at sign time by
 * the oesign tool.
 *
 * @param[in] PRODUCT_ID ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param[in] SECURITY_VERSION ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param[in] EXTENDED_PRODUCT_ID ISV assigned Extended Product ID (ISVEXTPRODID)
 *  to use in the enclave signature (SGX2 feature)
 * @param[in] FAMILY_ID ISV assigned Product Family ID (ISVFAMILYID)
 * to use in the enclave signature (SGX2 feature)
 * @param[in] ALLOW_DEBUG If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param[in] REQUIRE_KSS If true, allows the enclave to be created with
 * KSS properties (SGX2 feature)
 * @param[in] CAPTURE_PF_GP_EXCEPTIONS If true, allows the enclave to capture
 * #PF and #GP exceptions if the CPU supports the feature. The setting is
 * ignored otherwise (SGX2 feature)
 * @param[in] CREATE_ZERO_BASE_ENCLAVE If true, allows enclave to be created
 * with a base address of 0x0. Else, the usual enclave creation logic is
 * followed. Currently available only for SGX on linux. On windows,
 * the input should be false.
 * @param[in] ENCLAVE_START_ADDRESS If CREATE_ZERO_BASE_ENCLAVE is set, the
 * enclave image start address. Must be higher than value in
 * /proc/sys/vm/mmap_min_addr. Currently available only for SGX on linux. On
 * windows, the input should be 0.
 * @param[in] HEAP_PAGE_COUNT Number of heap pages to allocate in the enclave
 * @param[in] STACK_PAGE_COUNT Number of stack pages per thread to reserve in
 * the enclave
 * @param[in] TCS_COUNT Number of concurrent threads in an enclave to support
 */
 #define OE_SET_ENCLAVE_SGX2(                                             \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    EXTENDED_PRODUCT_ID,                                                  \
    FAMILY_ID,                                                            \
    ALLOW_DEBUG,                                                          \
    CAPTURE_PF_GP_EXCEPTIONS,                                             \
    REQUIRE_KSS,                                                          \
    CREATE_ZERO_BASE_ENCLAVE,                                             \
    ENCLAVE_START_ADDRESS,                                                \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)                                                            \
 _OE_SET_ENCLAVE_SGX_IMPL(                                                \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    EXTENDED_PRODUCT_ID,                                                  \
    FAMILY_ID,                                                            \
    ALLOW_DEBUG,                                                          \
    REQUIRE_KSS,                                                          \
    CAPTURE_PF_GP_EXCEPTIONS,                                             \
    CREATE_ZERO_BASE_ENCLAVE,                                             \
    ENCLAVE_START_ADDRESS,                                                \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)

// clang-format on

#endif /* _OE_BITS_SGX_SGXPROPERTIES_H */
