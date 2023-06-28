// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_TDX_TDXQUOTE_H
#define _OE_BITS_TDX_TDXQUOTE_H

#include <openenclave/bits/sgx/sgxtypes.h>

OE_EXTERNC_BEGIN

#define OE_TDX_QUOTE_VERSION (4)

typedef struct _tee_tcb_svn
{
    uint8_t seam0;
    uint8_t seam1;
    uint8_t reserved[14];
} tee_tcb_svn_t;

typedef struct _tdx_attributes_t
{
    union
    {
        struct
        {
            uint8_t debug : 1;
            uint8_t reserved : 7;
        } d;
        uint8_t u;
    } tud;
    union
    {
        struct
        {
            uint8_t reserved0[2];
            uint8_t reserved1 : 4;
            uint8_t sept_ve_disable : 1;
            uint8_t reserved2 : 1;
            uint8_t pks : 1;
            uint8_t kl : 1;
        } d;
        uint8_t u[3];
    } sec;
    union
    {
        struct
        {
            uint8_t reserved0[3];
            uint8_t reserved1 : 7;
            uint8_t perfmon : 1;
        } d;
        uint8_t u[4];
    } other;
} tdx_attributes_t;

OE_PACK_BEGIN
typedef struct _tdx_report_body_t
{
    /* (0) */
    tee_tcb_svn_t tee_tcb_svn;

    /* (16) */
    uint8_t mrseam[48];

    /* (64) */
    uint8_t mrseamsigner[48];

    /* (112) */
    uint8_t seam_attributes[8];

    /* (120) */
    tdx_attributes_t td_attributes;

    /* (128) */
    uint8_t xfam[8];

    /* (136) */
    uint8_t mrtd[48];

    /* (184) */
    uint8_t mrconfigid[48];

    /* (232) */
    uint8_t mrowner[48];

    /* (280) */
    uint8_t mrownerconfig[48];

    /* (328) */
    uint8_t rtmr0[48];

    /* (376) */
    uint8_t rtmr1[48];

    /* (424) */
    uint8_t rtmr2[48];

    /* (472) */
    uint8_t rtmr3[48];

    /* (520) */
    uint8_t report_data[64];
} tdx_report_body_t;
OE_PACK_END

OE_PACK_BEGIN
typedef struct _tdx_quote_t
{
    /* (0) */
    uint16_t version;

    /* (2) */
    uint16_t sign_type;

    /* (4) */
    uint32_t tee_type;

    /* (8) */
    uint16_t qe_svn;

    /* (10) */
    uint16_t pce_svn;

    /* (12) */
    uint8_t uuid[16];

    /* (28) */
    uint8_t user_data[SGX_USERDATA_SIZE];

    /* (48) */
    tdx_report_body_t report_body;

    /* (656) */
    uint32_t signature_len;

    /* (660) */
    OE_ZERO_SIZED_ARRAY uint8_t signature[];
} tdx_quote_t;
OE_PACK_END

/*
**==============================================================================
**
** tdx_quote_auth_data_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _tdx_quote_auth_data
{
    /* (0) Pair of 256 bit ECDSA Signature. */
    sgx_ecdsa256_signature_t signature;

    /* (64) Pair of 256 bit ECDSA Key. */
    sgx_ecdsa256_key_t attestation_key;

    /* Place holder for sgx_qe_cert_data_t
     * where the data holds tdx_qe_report_certification_data_t*/
    uint8_t certification_data[];
} tdx_quote_auth_data_t;
OE_PACK_END

OE_STATIC_ASSERT(OE_OFFSETOF(tdx_quote_auth_data_t, signature) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(tdx_quote_auth_data_t, attestation_key) == 64);
OE_STATIC_ASSERT(sizeof(tdx_quote_auth_data_t) == 128);

OE_PACK_BEGIN
typedef struct _tdx_qe_report_certification_data_t
{
    /* (0) Quoting Enclave Report Body */
    sgx_report_body_t qe_report_body;

    /* (384) Quoting Enclave Report Body Signature */
    sgx_ecdsa256_signature_t signature;

    /* Place holder for sgx_qe_auth_data_t and sgx_qe_cert_data_t */
    uint8_t auth_certification_data[];
} tdx_qe_report_certification_data_t;
OE_PACK_END

OE_EXTERNC_END

#endif /* _OE_BITS_TDX_TDXQUOTE_H */
