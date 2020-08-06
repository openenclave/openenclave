// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file sgx/evidence.h
 *
 * This file defines helper functions for verifying an SGX report.
 *
 */

#ifndef _OE_ATTESTATION_SGX_EVIDENCE_H
#define _OE_ATTESTATION_SGX_EVIDENCE_H

#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

#define OE_FORMAT_UUID_SGX_ECDSA_P256                                     \
    {                                                                     \
        0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, \
            0x25, 0xd2, 0xfb, 0xcd, 0x8c                                  \
    }

#define OE_FORMAT_UUID_SGX_ECDSA_P256_REPORT                              \
    {                                                                     \
        0xc8, 0x30, 0x34, 0x54, 0xd9, 0x23, 0x4c, 0x2c, 0xa6, 0x91, 0xdf, \
            0x7d, 0xef, 0x46, 0x0a, 0x76                                  \
    }

#define OE_FORMAT_UUID_SGX_ECDSA_P256_QUOTE                               \
    {                                                                     \
        0x19, 0x23, 0xd9, 0x1e, 0x12, 0xd2, 0x4c, 0x72, 0xb2, 0x20, 0x25, \
            0xcd, 0x8d, 0xac, 0xe8, 0x71                                  \
    }

#define OE_FORMAT_UUID_SGX_ECDSA_P384                                     \
    {                                                                     \
        0xac, 0x17, 0x68, 0x6f, 0x37, 0x0c, 0x46, 0x24, 0x91, 0x4a, 0x32, \
            0xdc, 0x90, 0x97, 0x3d, 0x12                                  \
    }

#define OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION                              \
    {                                                                     \
        0x09, 0x26, 0x8c, 0x33, 0x6e, 0x0b, 0x45, 0xe5, 0x8a, 0x27, 0x15, \
            0x64, 0x4d, 0x0e, 0xf8, 0x9a                                  \
    }

#define OE_FORMAT_UUID_SGX_EPID_LINKABLE                                  \
    {                                                                     \
        0xf2, 0x28, 0xaa, 0x3f, 0xde, 0x4d, 0x49, 0xd3, 0x88, 0x4c, 0xb2, \
            0xaa, 0x87, 0xa5, 0x0d, 0xa6                                  \
    }

#define OE_FORMAT_UUID_SGX_EPID_UNLINKABLE                                \
    {                                                                     \
        0x5c, 0x35, 0xd2, 0x90, 0xa2, 0xc2, 0x4c, 0x55, 0x9e, 0x13, 0x5a, \
            0xd7, 0x32, 0x74, 0x6c, 0x88                                  \
    }

#define OE_FORMAT_UUID_SGX_UNKNOWN                                        \
    {                                                                     \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00                                  \
    }

/**
 * SGX specific claim: SGX Quote verification collateral.
 */
#define OE_CLAIM_SGX_TCB_INFO "sgx_tcb_info"
#define OE_CLAIM_SGX_TCB_ISSUER_CHAIN "sgx_tcb_issuer_chain"
#define OE_CLAIM_SGX_PCK_CRL "sgx_pck_crl"
#define OE_CLAIM_SGX_ROOT_CA_CRL "sgx_root_ca_crl"
#define OE_CLAIM_SGX_CRL_ISSUER_CHAIN "sgx_crl_issuer_chain"
#define OE_CLAIM_SGX_QE_ID_INFO "sgx_qe_id_info"
#define OE_CLAIM_SGX_QE_ID_ISSUER_CHAIN "sgx_qe_id_issuer_chain"
#define OE_SGX_CLAIMS_COUNT 7

/**
 * Additional SGX specific claim: for the report data embedded in the SGX quote.
 */
#define OE_CLAIM_SGX_REPORT_DATA "sgx_report_data"

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_EVIDENCE_H */
