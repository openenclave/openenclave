// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_REPORT_H_
#define _OE_INCLUDE_REPORT_H_

#include <openenclave/bits/types.h>
#include <openenclave/internal/sgxtypes.h>

/*
**==============================================================================
**
** _oe_get_revocation_info_args
**
**==============================================================================
*/
typedef struct _oe_get_revocation_info_args
{
    oe_result_t result;              /* out */
    uint8_t fmspc[6];                /* in */
    const char* crl_urls[3];         /* in */
    uint32_t num_crl_urls;           /* in */
    uint8_t* tcb_info;               /* out */
    size_t tcb_info_size;            /* out */
    uint8_t* tcb_issuer_chain;       /* out */
    size_t tcb_issuer_chain_size;    /* out */
    uint8_t* crl[3];                 /* out */
    size_t crl_size[3];              /* out */
    uint8_t* crl_issuer_chain[3];    /* out */
    size_t crl_issuer_chain_size[3]; /* out */
    uint8_t* buffer;                 /* out */
} oe_get_revocation_info_args_t;

/*
**==============================================================================
**
** _oe_get_qe_identity_info_args
**
**==============================================================================
*/
typedef struct _oe_get_qe_identity_info_args
{
    uint8_t* qe_id_info;      /* out */
    size_t qe_id_info_size;   /* out */
    uint8_t* issuer_chain;    /* out */
    size_t issuer_chain_size; /* out */
    uint8_t* host_out_buffer; /* out */
} oe_get_qe_identity_info_args_t;

/*
**==============================================================================
**
** oe_collaterals_header_t
**
**==============================================================================
*/
typedef struct _oe_collaterals_header
{
    /** Size of the collaterals */
    uint32_t collaterals_size;

    /** Collaterals data **/
    uint8_t collaterals[];

} oe_collaterals_header_t;

OE_STATIC_ASSERT(sizeof(oe_collaterals_header_t) == 4);

/*
**==============================================================================
**
** oe_collaterals_t
**
** Structure with the collateral contents.  The collaterals are used during
** the verification of the oe_report_t.
**
**==============================================================================
*/
typedef struct _oe_collaterals
{
    oe_get_qe_identity_info_args_t qe_id_info;
    oe_get_revocation_info_args_t revocation_info;

    /* Time the collaterals were generated */
    char creation_datetime[24];

    uint64_t app_collaterals_size;
    uint8_t app_collaterals[];

} oe_collaterals_t;

OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_collaterals_header_t, collaterals) ==
    sizeof(oe_collaterals_header_t));

#define OE_COLLATERALS_HEADER_SIZE (sizeof(oe_collaterals_header_t))
#define OE_COLLATERALS_BODY_SIZE (sizeof(oe_collaterals_t))
#define OE_COLLATERALS_SIZE \
    (OE_COLLATERALS_HEADER_SIZE + OE_COLLATERALS_BODY_SIZE)

/*
**==============================================================================
**
** oe_report_type_t
**
**==============================================================================
*/
typedef enum _oe_report_type
{
    OE_REPORT_TYPE_SGX_LOCAL = 1,
    OE_REPORT_TYPE_SGX_REMOTE = 2,
    __OE_REPORT_TYPE_MAX = OE_ENUM_MAX
} oe_report_type_t;

/*
**==============================================================================
**
** oe_report_header_t
**
**==============================================================================
*/
typedef struct _oe_report_header
{
    uint32_t version;
    oe_report_type_t report_type;
    uint64_t report_size;
    uint8_t report[];
} oe_report_header_t;

OE_STATIC_ASSERT(sizeof(oe_report_header_t) == 16);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_report_header_t, report) == sizeof(oe_report_header_t));

// ISO(1).ANSI(2).USA(840).Microsoft(113556).ACC(10).Classes(1).Subclass(1)
#define X509_OID_FOR_QUOTE_EXT                               \
    {                                                        \
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x0A, 0x01, 0x01 \
    }
#define X509_OID_FOR_QUOTE_STRING "1.2.840.113556.10.1.1"

// For old OE reports.
#define OE_REPORT_HEADER_VERSION (1)

// For attestation plugin reports.
#define OE_ATTESTATION_HEADER_VERSION (2)

#endif //_OE_INCLUDE_REPORT_H_
