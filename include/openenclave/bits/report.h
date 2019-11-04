// Copyright (c) Open Enclave SDK contributors.
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

/**
 * The size of a UUID in bytes.
 */
#define UUID_SIZE 16

/**
 * Struct containing the definition for an UUID.
 */
typedef struct
{
    uint8_t b[UUID_SIZE];
} uuid_t;

/**
 * Claims struct used for claims parameters for the attestation plugins.
 */
typedef struct _oe_claim
{
    char* name;
    uint8_t* value;
    size_t value_size;
} oe_claim_t;

/**
 * Claims that are known to OE that every attestation plugin should output.
 */
#define OE_CLAIM_ID_VERSION "id_version"
#define OE_CLAIM_SECURITY_VERSION "security_version"
#define OE_CLAIM_ATTRIBUTES "attributes"
#define OE_CLAIM_UNIQUE_ID "unique_id"
#define OE_CLAIM_SIGNER_ID "signer_id"
#define OE_CLAIM_PRODUCT_ID "product_id"
#define OE_CLAIM_PLUGIN_UUID "plugin_uuid"
#define OE_REQUIRED_CLAIMS_COUNT 7
static const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT] = {
    OE_CLAIM_ID_VERSION,
    OE_CLAIM_SECURITY_VERSION,
    OE_CLAIM_ATTRIBUTES,
    OE_CLAIM_UNIQUE_ID,
    OE_CLAIM_SIGNER_ID,
    OE_CLAIM_PRODUCT_ID,
    OE_CLAIM_PLUGIN_UUID};

/**
 * Additional optional claims that are known to OE that plugins can output.
 */
#define OE_CLAIM_VALIDITY_FROM "validity_from"
#define OE_CLAIM_VALIDITY_UNTIL "validity_until"
#define OE_OPTIONAL_CLAIMS_COUNT 2
static const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT] = {
    OE_CLAIM_VALIDITY_FROM,
    OE_CLAIM_VALIDITY_UNTIL};

/**
 * Supported policies for validation by the verifier attestation plugin.
 * Only time is supported for now.
 */
typedef enum _oe_policy_type
{
    /**
     * Enforces that time fields in the endorsements will be checked in
     * with the given time rather than the endorsement creation time.
     *
     * The policy will be in the form of `oe_datetime_t`.
     */
    OE_POLICY_ENDORSEMENTS_TIME = 1
} oe_policy_type_t;

/**
 * Generic struct for defining policy for the attestation plugins.
 */
typedef struct _oe_policy
{
    oe_policy_type_t type;
    void* policy;
    size_t policy_size;
} oe_policy_t;

OE_EXTERNC_END

#endif /* _OE_BITS_REPORT_H */
