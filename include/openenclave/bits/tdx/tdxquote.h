// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_TDX_TDXQUOTE_H
#define _OE_BITS_TDX_TDXQUOTE_H

#include <openenclave/bits/sgx/sgxtypes.h>

OE_EXTERNC_BEGIN

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
            uint8_t reserved0 : 3;
            uint8_t hgs_plus_prof : 1;
            uint8_t perf_prof : 1;
            uint8_t pmt_prof : 1;
            uint8_t reserved1 : 1;
            uint8_t reserved2;
        } d;
        uint8_t u[2];
    } tud_tup;
    union
    {
        struct
        {
            uint8_t icssd : 1;
            uint8_t servtd_ext : 1;
            uint8_t reserved0 : 6;
            uint8_t reserved1 : 3;
            uint8_t lass : 1;
            uint8_t sept_ve_disable : 1;
            uint8_t migratable : 1;
            uint8_t pks : 1;
            uint8_t kl : 1;
        } d;
        uint8_t u[2];
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
typedef struct _tdx_report_body_v5_t
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

    /* (584) */
    tee_tcb_svn_t tee_tcb_svn2;

    /* (600) */
    uint8_t mrservicetd[48];
} tdx_report_body_v5_t;
OE_PACK_END

/*
** TDX report body type 4 (TD Quote body v1.5_ex). Present when the TD
** ATTRIBUTES.SERVTD_EXT (bit 17) is set. Extends the v1.5 (type 3) body with
** the Service-TD extension fields, allowing a verifier to observe both the
** initial and current bound Service-TD measurement and attributes, plus the
** platform TCB context (CPU SVN, TEE TCB SVN, FMSPC) recorded when the
** Service-TD was first bound. The first 648 bytes are identical to
** tdx_report_body_v5_t.
*/
OE_PACK_BEGIN
typedef struct _tdx_report_body_v1_5_ex_t
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

    /* (584) */
    tee_tcb_svn_t tee_tcb_svn2;

    /* (600) */
    uint8_t mrservicetd[48];

    /* (648) Service-TD extension fields (v1.5_ex) */
    uint8_t vmid;

    /* (649) */
    uint8_t td_id[32];

    /* (681) */
    uint8_t devinfo[48];

    /* (729) SHA384 of the Service-TD bound at TD build time. */
    uint8_t init_server_td_hash[48];

    /* (777) Service-TD ATTRIBUTES recorded at TD build time. */
    uint8_t init_server_td_attr[8];

    /* (785) Platform CPU SVN recorded when the Service-TD was first bound. */
    uint8_t init_cpu_svn[16];

    /* (801) Platform TEE TCB SVN recorded when the Service-TD was first bound.
     */
    tee_tcb_svn_t init_tee_tcb_svn;

    /* (817) Platform FMSPC recorded when the Service-TD was first bound. */
    uint8_t init_tee_fmspc[12];

    /* (829) SHA384 of the currently bound Service-TD. */
    uint8_t curr_server_td_hash[48];

    /* (877) ATTRIBUTES of the currently bound Service-TD. */
    uint8_t curr_server_td_attr[8];
} tdx_report_body_v1_5_ex_t;
OE_PACK_END

OE_STATIC_ASSERT(OE_OFFSETOF(tdx_report_body_v1_5_ex_t, mrservicetd) == 600);
OE_STATIC_ASSERT(OE_OFFSETOF(tdx_report_body_v1_5_ex_t, vmid) == 648);
OE_STATIC_ASSERT(
    OE_OFFSETOF(tdx_report_body_v1_5_ex_t, init_server_td_hash) == 729);
OE_STATIC_ASSERT(
    OE_OFFSETOF(tdx_report_body_v1_5_ex_t, init_server_td_attr) == 777);
OE_STATIC_ASSERT(OE_OFFSETOF(tdx_report_body_v1_5_ex_t, init_cpu_svn) == 785);
OE_STATIC_ASSERT(
    OE_OFFSETOF(tdx_report_body_v1_5_ex_t, init_tee_tcb_svn) == 801);
OE_STATIC_ASSERT(OE_OFFSETOF(tdx_report_body_v1_5_ex_t, init_tee_fmspc) == 817);
OE_STATIC_ASSERT(
    OE_OFFSETOF(tdx_report_body_v1_5_ex_t, curr_server_td_hash) == 829);
OE_STATIC_ASSERT(
    OE_OFFSETOF(tdx_report_body_v1_5_ex_t, curr_server_td_attr) == 877);
OE_STATIC_ASSERT(sizeof(tdx_report_body_v1_5_ex_t) == 885);

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

OE_PACK_BEGIN
typedef struct _tdx_quote_v5_t
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
    uint16_t type;

    /* (50) */
    uint32_t size;

    /* (54) */
    OE_ZERO_SIZED_ARRAY uint8_t body[];
} tdx_quote_v5_t;
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

    /* Place holder for tdx_qe_certification_data_t. */
    uint8_t certification_data[];
} tdx_quote_auth_data_t;
OE_PACK_END

OE_STATIC_ASSERT(OE_OFFSETOF(tdx_quote_auth_data_t, signature) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(tdx_quote_auth_data_t, attestation_key) == 64);
OE_STATIC_ASSERT(sizeof(tdx_quote_auth_data_t) == 128);

#define TDX_QE_CERTIFICATION_DATA_TYPE_PCK_CERT_CHAIN 5
#define TDX_QE_CERTIFICATION_DATA_TYPE_QE_REPORT 6

OE_PACK_BEGIN
typedef struct _tdx_qe_certification_data_t
{
    /* (0) Certification Data Type */
    uint16_t type;

    /* (2) Certification Data Size */
    uint32_t size;

    /* Place holder for tdx_qe_report_certification_data_t */
    uint8_t certification_data[];
} tdx_qe_certification_data_t;
OE_PACK_END

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
