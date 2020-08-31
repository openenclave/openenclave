// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_REPORT_H_
#define _OE_INCLUDE_REPORT_H_

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>

#if __x86_64__ || _M_X64
#include <openenclave/bits/sgx/sgxtypes.h>
#endif

/*
**==============================================================================
**
** _oe_get_sgx_quote_verification_collateral_args
**
**==============================================================================
*/
typedef struct _oe_get_sgx_quote_verification_collateral_args
{
    oe_result_t result;                   /* out */
    uint8_t fmspc[6];                     /* in */
    uint8_t collateral_provider;          /* in */
    uint8_t* tcb_info;                    /* out */
    size_t tcb_info_size;                 /* out */
    uint8_t* tcb_info_issuer_chain;       /* out */
    size_t tcb_info_issuer_chain_size;    /* out */
    uint8_t* pck_crl;                     /* out */
    size_t pck_crl_size;                  /* out */
    uint8_t* pck_crl_issuer_chain;        /* out */
    size_t pck_crl_issuer_chain_size;     /* out */
    uint8_t* root_ca_crl;                 /* out */
    size_t root_ca_crl_size;              /* out */
    uint8_t* qe_identity;                 /* out */
    size_t qe_identity_size;              /* out */
    uint8_t* qe_identity_issuer_chain;    /* out */
    size_t qe_identity_issuer_chain_size; /* out */
    uint8_t* host_out_buffer;             /* out */
} oe_get_sgx_quote_verification_collateral_args_t;

// Collateral provider for sgx quote verification
#define CRL_CA_PROCESSOR (1)
#define CRL_CA_PLATFORM (2)

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

#define X509_OID_FOR_NEW_QUOTE_EXT                           \
    {                                                        \
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x69, 0x01 \
    }
#define X509_OID_FOR_NEW_QUOTE_STRING "1.3.6.1.4.1.311.105.1"

// For old OE reports.
#define OE_REPORT_HEADER_VERSION (1)

#endif //_OE_INCLUDE_REPORT_H_
