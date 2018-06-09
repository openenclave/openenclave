// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_REPORT_H
#define _OE_REPORT_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

/*
 * Options passed to GetReport functions on host and enclave.
 * Default value (0) is local attestation.
 */
#define OE_REPORT_OPTIONS_REMOTE_ATTESTATION 0x00000001

#define OE_REPORT_DATA_SIZE 64

// Up to 10 KB reports are supported.
#define OE_MAX_REPORT_SIZE (10 * 1024)

// Fixed identity property sizes for OEv1
#define OE_UNIQUE_ID_SIZE 32
#define OE_AUTHOR_ID_SIZE 32
#define OE_PRODUCT_ID_SIZE 16

// Enclave report attribute bit masks
#define OE_REPORT_ATTRIBUTES_DEBUG 0x0000000000000001ULL
#define OE_REPORT_ATTRIBUTES_REMOTE 0x0000000000000002ULL
#define OE_REPORT_ATTRIBUTES_RESERVED \
    (~(OE_REPORT_ATTRIBUTES_DEBUG | OE_REPORT_ATTRIBUTES_REMOTE))

typedef struct _oe_identity
{
    uint32_t idVersion;
    uint32_t securityVersion;
    uint64_t attributes;
    uint8_t uniqueID[OE_UNIQUE_ID_SIZE];
    uint8_t authorID[OE_AUTHOR_ID_SIZE];
    uint8_t productID[OE_PRODUCT_ID_SIZE];
} oe_identity_t;

/*
 * oe_report_t structure holds the parsed form of a report.
 */
typedef struct _oe_report
{
    /* Size of the oe_report_t structure. */
    uint32_t size;

    /* The enclave type. Currently always OE_ENCLAVE_TYPE_SGX. */
    oe_enclave_type_t type;

    /* Pointer to report data field within the report byte-stream supplied to
     * oe_parse_report.*/
    uint8_t* reportData;
    uint32_t reportDataSize;

    /* Pointer to report body field within the report byte-stream supplied to
     * oe_parse_report. */
    uint8_t* enclaveReport;
    uint32_t enclaveReportSize;

    oe_identity_t identity;
} oe_report_t;

OE_EXTERNC_END

#endif /* _OE_REPORT_H */
