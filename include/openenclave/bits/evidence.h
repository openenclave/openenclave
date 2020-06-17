// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file evidence.h
 *
 * This file defines structures and options for SGX evidence generation and
 * verification.
 *
 */
#ifndef _OE_BITS_EVIDENCE_H
#define _OE_BITS_EVIDENCE_H

#include "defs.h"
#include "types.h"

#include "report.h"

OE_EXTERNC_BEGIN

/**
 * Bit mask for evidence of an SGX enclave in debug mode.
 */
#define OE_EVIDENCE_ATTRIBUTES_SGX_DEBUG OE_REPORT_ATTRIBUTES_DEBUG
/**
 * Bit mask for evidence of an SGX enclave for remote attestation
 */
#define OE_EVIDENCE_ATTRIBUTES_SGX_REMOTE OE_REPORT_ATTRIBUTES_REMOTE
/**
 * Reserved bits.
 */
#define OE_EVIDENCE_ATTRIBUTES_RESERVED \
    (~(OE_EVIDENCE_ATTRIBUTES_SGX_DEBUG | OE_EVIDENCE_ATTRIBUTES_SGX_REMOTE))

/**
 * The size of a UUID in bytes.
 */
#define OE_UUID_SIZE 16

/**
 * Struct containing the definition for an UUID.
 */
typedef struct _oe_uuid_t
{
    uint8_t b[OE_UUID_SIZE];
} oe_uuid_t;

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
#define OE_CLAIM_FORMAT_UUID "format_uuid"
#define OE_REQUIRED_CLAIMS_COUNT 7
// This array is needed for tests
extern const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT];

/**
 * Additional optional claims that are known to OE that plugins can output.
 */
#define OE_CLAIM_VALIDITY_FROM "validity_from"
#define OE_CLAIM_VALIDITY_UNTIL "validity_until"
#define OE_OPTIONAL_CLAIMS_COUNT 2
// This array is needed for tests
extern const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT];

/**
 * Supported policies for validation by the verifier attestation plugin.
 * Only time is supported for now.
 */
typedef enum _oe_policy_type
{
    /**
     * Enforces that time fields in the endorsements will be checked
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

#endif /* _OE_BITS_EVIDENCE_H */
