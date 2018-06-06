// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file report.h
 *
 * This file defines structures and options passed to GetReport functions.
 *
 */
#ifndef _OE_REPORT_H
#define _OE_REPORT_H

#include "defs.h"

OE_EXTERNC_BEGIN

/**
 * Options passed to GetReport functions on host and enclave.
 * Default value (0) is local attestation.
 */
#define OE_REPORT_OPTIONS_REMOTE_ATTESTATION 0x00000001

#define OE_REPORT_DATA_SIZE 64

#define OE_MAX_REPORT_SIZE (1 * 1024)

/**
 * @cond DEV
 */
// Fixed identity property sizes for OEv1
#define OE_UNIQUE_ID_SIZE 32
#define OE_AUTHOR_ID_SIZE 32
#define OE_PRODUCT_ID_SIZE 16

// Enclave report attribute bit masks
#define OE_REPORT_ATTRIBUTES_DEBUG 0x0000000000000001ULL
#define OE_REPORT_ATTRIBUTES_REMOTE 0x0000000000000002ULL
#define OE_REPORT_ATTRIBUTES_RESERVED \
    (~(OE_REPORT_ATTRIBUTES_DEBUG | OE_REPORT_ATTRIBUTES_REMOTE))

/**
 * @endcond
 */

/**
 * OE_Identity structure
 */
typedef struct _OE_Identity
{
    uint32_t idVersion;       /**< Version number */
    uint32_t securityVersion; /**< ISVN - the security version */
    uint64_t attributes; /**< Values of the attributes flags for the enclave */
    uint8_t uniqueID[OE_UNIQUE_ID_SIZE]; /**< Maps to mrenclave property of the
                                            local report */
    uint8_t authorID[OE_AUTHOR_ID_SIZE]; /**< Maps to mrsigner property of the
                                            local report */
    uint8_t
        productID[OE_PRODUCT_ID_SIZE]; /**< ISVPRODID - Enclave Product ID */
} OE_Identity;

/**
 * OE_Report structure holds the parsed form of a report.
 */
typedef struct _OE_Report
{
    uint32_t size; /**< Size of the OE_Report structure. */

    OE_EnclaveType type; /**< @OE_EnclaveType The enclave type. Currently always
                              OE_ENCLAVE_TYPE_SGX. */

    uint8_t* reportData; /**< Pointer to report data field within the report
                            byte-stream supplied to OE_ParseReport */

    uint32_t reportDataSize; /**< Size of reportData */

    uint8_t* enclaveReport; /**< Pointer to report body field within the report
                                 byte-stream supplied to OE_ParseReport. */

    uint32_t enclaveReportSize; /**< Size of enclaveReport */

    OE_Identity identity; /**< Contains the IDs and attributes that are
                   part of OE_Identity */
} OE_Report;

OE_EXTERNC_END

#endif /* _OE_REPORT_H */
