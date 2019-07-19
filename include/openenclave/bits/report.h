// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file report.h
 *
 * This file defines structures and options passed to oe_get_report functions.
 *
 */
#ifndef _OE_BITS_REPORT_H
#define _OE_BITS_REPORT_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

/**
 * Flags passed to oe_get_report functions on host and enclave.
 * Default value (0) is local attestation.
 */
#define OE_REPORT_FLAGS_REMOTE_ATTESTATION 0x00000001

/**
 * Size of embedded data in a local report.
 */
#define OE_REPORT_DATA_SIZE 64

/**
 * Maximum report size supported by OE. This is 10 KB.
 */
#define OE_MAX_REPORT_SIZE (10 * 1024)

/**
 * @cond DEV
 */
// Fixed identity property sizes for OEv1
/**
 * Size of the enclave's unique ID in bytes.
 */
#define OE_UNIQUE_ID_SIZE 32
/**
 * Size of the enclave's signer ID in bytes.
 */
#define OE_SIGNER_ID_SIZE 32
/**
 * Size of the enclave's product ID in bytes.
 */
#define OE_PRODUCT_ID_SIZE 16

/**
 * Bit mask for a debug report.
 */
#define OE_REPORT_ATTRIBUTES_DEBUG 0x0000000000000001ULL
/**
 * Bit mask for a remote report.
 */
#define OE_REPORT_ATTRIBUTES_REMOTE 0x0000000000000002ULL
/**
 * Reserved bits.
 */
#define OE_REPORT_ATTRIBUTES_RESERVED \
    (~(OE_REPORT_ATTRIBUTES_DEBUG | OE_REPORT_ATTRIBUTES_REMOTE))

/**
 * @endcond
 */

/**
 * Structure to represent the identity of an enclave.
 * This structure is expected to change in future.
 * Newer fields are always added at the end and fields are never removed.
 * Before accessing a field, the enclave must first check that the field is
 * valid using the id_version and the table below:
 *
 * id_version | Supported fields
 * -----------| --------------------------------------------------------------
 *     0      | security_version, attributes, unique_id, signer_id, product_id
 */
typedef struct _oe_identity
{
    /** Version of the oe_identity_t structure */
    uint32_t id_version;

    /** Security version of the enclave. For SGX enclaves, this is the
     *  ISVN value */
    uint32_t security_version;

    /** Values of the attributes flags for the enclave -
     *  OE_REPORT_ATTRIBUTES_DEBUG: The report is for a debug enclave.
     *  OE_REPORT_ATTRIBUTES_REMOTE: The report can be used for remote
     *  attestation */
    uint64_t attributes;

    /** The unique ID for the enclave.
     * For SGX enclaves, this is the MRENCLAVE value */
    uint8_t unique_id[OE_UNIQUE_ID_SIZE];

    /** The signer ID for the enclave.
     * For SGX enclaves, this is the MRSIGNER value */
    uint8_t signer_id[OE_SIGNER_ID_SIZE];

    /** The Product ID for the enclave.
     * For SGX enclaves, this is the ISVPRODID value. */
    uint8_t product_id[OE_PRODUCT_ID_SIZE];
} oe_identity_t;
/**< typedef struct _oe_identity oe_identity_t*/

/**
 * Structure to hold the parsed form of a report.
 */
typedef struct _oe_report
{
    /** Size of the oe_report_t structure. */
    size_t size;

    /** The enclave type. Currently always OE_ENCLAVE_TYPE_SGX. */
    oe_enclave_type_t type;

    /** Size of report_data */
    size_t report_data_size;

    /** Size of enclave_report */
    size_t enclave_report_size;

    /** Pointer to report data field within the report byte-stream supplied to
     * oe_parse_report */
    uint8_t* report_data;

    /** Pointer to report body field within the report byte-stream supplied to
     * oe_parse_report. */
    uint8_t* enclave_report;

    /** Contains the IDs and attributes that are part of oe_identity_t */
    oe_identity_t identity;
} oe_report_t;
/**< typedef struct _oe_report oe_report_t*/

/*
**==============================================================================
**
** oe_tee_evidence_type_t
**
**==============================================================================
*/
typedef enum _oe_tee_evidence_type_t
{
    OE_TEE_TYPE_SGX_LOCAL = 1,
    OE_TEE_TYPE_SGX_REMOTE = 2,
    OE_TEE_TYPE_CYRES_LOCAL = 3,
    OE_TEE_TYPE_CYRES_REMOTE = 4,
    OE_TEE_TYPE_CUSTOM = 5,
    __OE_TEE_TYPE_MAX = OE_ENUM_MAX
} oe_tee_evidence_type_t;

#define UUID_SIZE 16
typedef struct
{
    uint8_t b[UUID_SIZE];
} uuid_t;

#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
    ((uuid_t){{((a) >> 24) & 0xff,                         \
               ((a) >> 16) & 0xff,                         \
               ((a) >> 8) & 0xff,                          \
               (a)&0xff,                                   \
               ((b) >> 8) & 0xff,                          \
               (b)&0xff,                                   \
               ((c) >> 8) & 0xff,                          \
               (c)&0xff,                                   \
               (d0),                                       \
               (d1),                                       \
               (d2),                                       \
               (d3),                                       \
               (d4),                                       \
               (d5),                                       \
               (d6),                                       \
               (d7)}})

/*
**==============================================================================
**
** oe_evidence_header_t
**
**==============================================================================
*/
typedef struct _oe_evidence_header
{
    uint32_t version;
    oe_tee_evidence_type_t tee_evidence_type; // TEE type
    uuid_t evidence_format_uuid;   // uuid for specific attestation format
    uint32_t tee_evidence_size;    // not including custom evidence
    uint32_t custom_evidence_size; // size of custom evidence, which follows
                                   // right after report data
    uint8_t tee_evidence[];
} oe_evidence_header_t;

// name = value (a byte stream)
typedef struct _oe_claim_element_t
{
    char* name;
    size_t len;
    uint8_t* value;
} oe_claim_element_t;

OE_EXTERNC_END

#endif /* _OE_BITS_REPORT_H */
