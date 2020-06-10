// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXTYPES_H
#define _OE_SGXTYPES_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/epid.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_KEY_SIZE 384
#define OE_EXPONENT_SIZE 4

#ifndef OE_SHA256_SIZE
#define OE_SHA256_SIZE 32
#endif

#define SGX_FLAGS_INITTED 0x0000000000000001ULL
#define SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define SGX_FLAGS_PROVISION_KEY 0x0000000000000010ULL
#define SGX_FLAGS_EINITTOKEN_KEY 0x0000000000000020ULL

/* Legacy XFRM which includes basic feature bits required by SGX i.e. X87
 * (bit 0) and SSE state (bit 1)
 */
#define SGX_XFRM_LEGACY 0x0000000000000003ULL

/* AVX XFRM which includes AVX (bit 2) and SSE State (Bit 1) required by AVX */
#define SGX_XFRM_AVX 0x0000000000000006ULL

/* AVX512 - not supported by Intel SGX */
#define SGX_XFRM_AVX512 0x00000000000000E6ULL

/* MPX XFRM - not supported by Intel SGX */
#define SGX_XFRM_MPX 0x0000000000000018ULL

#define SGX_SECINFO_R 0x0000000000000000001
#define SGX_SECINFO_W 0x0000000000000000002
#define SGX_SECINFO_X 0x0000000000000000004
#define SGX_SECINFO_SECS 0x0000000000000000000
#define SGX_SECINFO_TCS 0x0000000000000000100
#define SGX_SECINFO_REG 0x0000000000000000200

#define SGX_SE_EPID_SIG_RL_VERSION 0x200
#define SGX_SE_EPID_SIG_RL_ID 0xE00

#define SGX_QUOTE_IV_SIZE 12

#define SGX_UNMASKED_EVENT 128 /* SGX EINIT error code */

#if __x86_64__ || _M_X64
OE_STATIC_ASSERT(SGX_FLAGS_DEBUG == OE_SGX_FLAGS_DEBUG);
OE_STATIC_ASSERT(SGX_FLAGS_MODE64BIT == OE_SGX_FLAGS_MODE64BIT);
#endif

/* Rename OE_? types to SGX_? to make SGX types more explicit */

/*
**==============================================================================
**
** SGX Instructions:
**
**==============================================================================
*/

#define ENCLU_INSTRUCTION 0xd7010f

typedef enum _sgx_enclu_leaf
{
    ENCLU_EREPORT = 0x00,
    ENCLU_EGETKEY = 0x01,
    ENCLU_EENTER = 0x02,
    ENCLU_ERESUME = 0x03,
    ENCLU_EEXIT = 0x04,
    ENCLU_EACCEPT = 0x05,
    ENCLU_EMODPE = 0x06,
    ENCLU_EACCEPTCOPY = 0x07,
    ENCLU_UNDEFINED = OE_ENUM_MAX,
} sgx_enclu_leaf_t;

OE_STATIC_ASSERT(sizeof(sgx_enclu_leaf_t) == sizeof(unsigned int));

/*
**==============================================================================
**
** sgx_attributes_t:
**
**==============================================================================
*/

/* Default value for sgx_attributes_t.flags */
#define SGX_ATTRIBUTES_DEFAULT_FLAGS 0x0000000000000006ULL

/* Default value for sgx_attributes_t.xfrm */
#define SGX_ATTRIBUTES_DEFAULT_XFRM 0x0000000000000003ULL

OE_PACK_BEGIN
typedef struct _sgx_attributes
{
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;
OE_PACK_END

OE_CHECK_SIZE(sizeof(sgx_attributes_t), 16);

/*
**==============================================================================
**
** sgx_sigstruct_t
**
**==============================================================================
*/

/* sgx_sigstruct_t.header: 06000000E100000000000100H */
#define SGX_SIGSTRUCT_HEADER "\006\000\000\000\341\000\000\000\000\000\001\000"
#define SGX_SIGSTRUCT_HEADER_SIZE (sizeof(SGX_SIGSTRUCT_HEADER) - 1)

/* sgx_sigstruct_t.header2: 01010000600000006000000001000000H */
#define SGX_SIGSTRUCT_HEADER2 \
    "\001\001\000\000\140\000\000\000\140\000\000\000\001\000\000\000"
#define SGX_SIGSTRUCT_HEADER2_SIZE (sizeof(SGX_SIGSTRUCT_HEADER2) - 1)

/* sgx_sigstruct_t.miscselect */
#define SGX_SIGSTRUCT_MISCSELECT 0x00000000

/* sgx_sigstruct_t.miscmask */
#define SGX_SIGSTRUCT_MISCMASK 0xffffffff

/* sgx_sigstruct_t.flags */
#define SGX_SIGSTRUCT_ATTRIBUTEMASK_FLAGS 0XfffffffffffffffbULL

/* sgx_sigstruct_t.xfrm */
#define SGX_SIGSTRUCT_ATTRIBUTEMASK_XFRM 0x0000000000000000ULL

/* 1808 bytes */
OE_PACK_BEGIN
typedef struct _sgx_sigstruct
{
    /* ======== HEADER-SECTION ======== */

    /* (0) must be (06000000E100000000000100H) */
    uint8_t header[12];

    /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
    uint32_t type;

    /* (16) Intel=0x8086, ISV=0x0000 */
    uint32_t vendor;

    /* (20) build date as yyyymmdd */
    uint32_t date;

    /* (24) must be (01010000600000006000000001000000H) */
    uint8_t header2[16];

    /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
    uint32_t swdefined;

    /* (44) Must be 0 */
    uint8_t reserved[84];

    /* ======== KEY-SECTION ======== */

    /* (128) Module Public Key (keylength=3072 bits) */
    uint8_t modulus[OE_KEY_SIZE];

    /* (512) RSA Exponent = 3 */
    uint8_t exponent[OE_EXPONENT_SIZE];

    /* (516) Signature over Header and Body (HEADER-SECTION | BODY-SECTION) */
    uint8_t signature[OE_KEY_SIZE];

    /* ======== BODY-SECTION ======== */

    /* (900) The MISCSELECT that must be set */
    uint32_t miscselect;

    /* (904) Mask of MISCSELECT to enforce */
    uint32_t miscmask;

    /* (908) Reserved. Must be 0. */
    uint8_t reserved2[20];

    /* (928) Enclave Attributes that must be set */
    sgx_attributes_t attributes;

    /* (944) Mask of Attributes to Enforce */
    sgx_attributes_t attributemask;

    /* (960) MRENCLAVE - (32 bytes) */
    uint8_t enclavehash[OE_SHA256_SIZE];

    /* (992) Must be 0 */
    uint8_t reserved3[32];

    /* (1024) ISV assigned Product ID */
    uint16_t isvprodid;

    /* (1026) ISV assigned SVN */
    uint16_t isvsvn;

    /* ======== BUFFER-SECTION ======== */

    /* (1028) Must be 0 */
    uint8_t reserved4[12];

    /* (1040) Q1 value for RSA Signature Verification */
    uint8_t q1[OE_KEY_SIZE];

    /* (1424) Q2 value for RSA Signature Verification */
    uint8_t q2[OE_KEY_SIZE];
} sgx_sigstruct_t;
OE_PACK_END

OE_CHECK_SIZE(sizeof(sgx_sigstruct_t), 1808);

#if __x86_64__ || _M_X64
OE_CHECK_SIZE(sizeof(sgx_sigstruct_t), OE_SGX_SIGSTRUCT_SIZE);
#endif

OE_CHECK_SIZE(
    sizeof((sgx_sigstruct_t*)NULL)->header,
    SGX_SIGSTRUCT_HEADER_SIZE);

OE_CHECK_SIZE(
    sizeof((sgx_sigstruct_t*)NULL)->header2,
    SGX_SIGSTRUCT_HEADER2_SIZE);

OE_INLINE const void* sgx_sigstruct_header(const sgx_sigstruct_t* ss)
{
    return ss;
}

OE_INLINE size_t sgx_sigstruct_header_size(void)
{
    return OE_OFFSETOF(sgx_sigstruct_t, modulus);
}

OE_INLINE const void* sgx_sigstruct_body(const sgx_sigstruct_t* ss)
{
    return &ss->miscselect;
}

OE_INLINE size_t sgx_sigstruct_body_size(void)
{
    return OE_OFFSETOF(sgx_sigstruct_t, reserved4) -
           OE_OFFSETOF(sgx_sigstruct_t, miscselect);
}

void __sgx_dump_sigstruct(const sgx_sigstruct_t* p);

/*
**==============================================================================
**
** sgx_secs_t:
**
**==============================================================================
*/

typedef struct _sgx_secs
{
    uint64_t size;          /* 0 */
    uint64_t base;          /* 8 */
    uint32_t ssaframesize;  /* 16 */
    uint32_t misc_select;   /* 20 */
    uint8_t reserved1[24];  /* 24 */
    uint64_t flags;         /* 48 */
    uint64_t xfrm;          /* 56 */
    uint32_t mrenclave[8];  /* 64 */
    uint8_t reserved2[32];  /* 96 */
    uint32_t mrsigner[8];   /* 128 */
    uint8_t reserved3[96];  /* 160 */
    uint16_t isvvprodid;    /* 256 */
    uint16_t isvsvn;        /* 258 */
    uint8_t reserved[3836]; /* 260 */
} sgx_secs_t;

OE_CHECK_SIZE(sizeof(sgx_secs_t), 4096);

/*
**==============================================================================
**
** sgx_secinfo_t:
**
**==============================================================================
*/

typedef struct _sgx_secinfo
{
    uint64_t flags;
    uint64_t reserved[7];
} OE_ALIGNED(128) sgx_secinfo_t;

/*
**==============================================================================
**
** sgx_exit_info:
**
**==============================================================================
*/

typedef union {
    struct
    {
        uint32_t vector : 8;
        uint32_t exit_type : 3;
        uint32_t mbz : 20;
        uint32_t valid : 1;
    } as_fields;
    uint32_t as_uint32;
} sgx_exit_info;

/*
**==============================================================================
**
** sgx_ssa_gpr_t:
**
**==============================================================================
*/

typedef struct sgx_ssa_gpr_t
{
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    sgx_exit_info exit_info;
    uint32_t reserved;
    uint64_t fs_base;
    uint64_t gs_base;
} sgx_ssa_gpr_t, *PSGX_SsaGpr;

/*
**==============================================================================
**
** sgx_launch_token_t
**
**==============================================================================
*/

typedef struct _sgx_launch_token
{
    unsigned char contents[1024];
} sgx_launch_token_t;

/*
**==============================================================================
**
** sgx_einittoken_t
**
**==============================================================================
*/

#define SGX_CPUSVN_SIZE 16
#define SGX_KEYID_SIZE 32
#define SGX_MAC_SIZE 16

OE_PACK_BEGIN
typedef struct _sgx_einittoken
{
    /* (0) 0=invalid, 1=valid */
    uint32_t valid;

    /* (4) must be zero */
    uint8_t reserved1[44];

    /* (48) attributes of the enclave */
    sgx_attributes_t attributes;

    /* (64) MRENCLAVE (hash of enclave) */
    uint8_t mrenclave[OE_SHA256_SIZE];

    /* (96) */
    uint8_t reserved2[32];

    /* (128) MRSIGNER of the enclave */
    uint8_t mrsigner[OE_SHA256_SIZE];

    /* (160) */
    uint8_t reserved3[32];

    /* (192) launch Enclave's CPUSVN */
    uint8_t cpusvnle[SGX_CPUSVN_SIZE];

    /* (208) launch enclave's ISVPRODID */
    uint16_t isvprodidle;

    /* (210) launch Enclave's ISVSVN */
    uint16_t isvsvnle;

    /* (212) Must be 0 */
    uint8_t reserved4[24];

    /* (236) */
    uint32_t maskedmiscselectle;

    /* (240) attributes of launch enclave */
    sgx_attributes_t maskedattributesle;

    /* (256) value for key wear-out protection */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (288) CMAC using Launch Token Key */
    uint8_t mac[SGX_MAC_SIZE];
} sgx_einittoken_t;
OE_PACK_END

OE_CHECK_SIZE(sizeof(sgx_einittoken_t), 304);

void __sgx_dump_einittoken(const sgx_einittoken_t* p);

/*
**==============================================================================
**
** sgx_tcs_t
**
**==============================================================================
*/

typedef struct _sgx_tcs
{
    /* (0) enclave execution state (0=available, 1=unavailable) */
    uint64_t state;

    /* (8) thread's execution flags */
    uint64_t flags;

    /* (16) offset to the base of the State Save Area (SSA) stack */
    uint64_t ossa;

    /* (24) Current slot of an SSA frame */
    uint32_t cssa;

    /* (28) Number of available slots for SSA frames */
    uint32_t nssa;

    /* (32) entry point where control is transferred upon EENTER */
    uint64_t oentry;

    /* (40) Value of asynchronous exit pointer saved at EENTER time */
    uint64_t aep;

    /* (48) Added to enclave base address to get the FS segment address */
    uint64_t fsbase;

    /* (56) Added to enclave base address to get the GS segment address */
    uint64_t gsbase;

    /* (64) Size to become the new FS limit in 32-bit mode */
    uint32_t fslimit;

    /* (68) Size to become the new GS limit in 32-bit mode */
    uint32_t gslimit;

    /* (72) reserved */
    union {
        uint8_t reserved[4024];

        /* (72) Enclave's entry point (defaults to _start) */
        void (*entry)(void);
    } u;
} sgx_tcs_t;

OE_CHECK_SIZE(sizeof(sgx_tcs_t), 4096);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, state), 0);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, flags), 8);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, ossa), 16);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, cssa), 24);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, nssa), 28);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, oentry), 32);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, aep), 40);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, fsbase), 48);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, gsbase), 56);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, fslimit), 64);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, gslimit), 68);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, u.reserved), 72);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_tcs_t, u.entry), 72);
/*
**==============================================================================
**
** sgx_target_info_t
**
**==============================================================================
*/

typedef struct _sgx_target_info
{
    /* (0) MRENCLAVE (hash of target enclave) */
    uint8_t mrenclave[OE_SHA256_SIZE];

    /* (32) ATTRIBUTES of target enclave */
    sgx_attributes_t attributes;

    /* (48) Reserved */
    uint8_t reserved1[4];

    /* (52) MISCSELECT field of target enclave */
    uint32_t misc_select;

    /* (56) Reserved */
    uint8_t reserved2[456];
} sgx_target_info_t;

OE_CHECK_SIZE(sizeof(sgx_target_info_t), 512);

/*
**==============================================================================
**
** sgx_epid_group_id_t
**
**==============================================================================
*/

typedef struct _sgx_epid_group_id
{
    uint8_t id[4];
} sgx_epid_group_id_t;

OE_CHECK_SIZE(sizeof(sgx_epid_group_id_t), 4);

/*
**==============================================================================
**
** sgx_report_data_t
**
**==============================================================================
*/

typedef struct _sgx_report_data
{
    unsigned char field[64];
} sgx_report_data_t;

OE_CHECK_SIZE(sizeof(sgx_report_data_t), 64);

/*
**==============================================================================
**
** sgx_report_t
**
**==============================================================================
*/

typedef struct _sgx_report_body
{
    /* (0) CPU security version */
    uint8_t cpusvn[SGX_CPUSVN_SIZE];

    /* (16) Selector for which fields are defined in SSA.MISC */
    uint32_t miscselect;

    /* (20) Reserved */
    uint8_t reserved1[28];

    /* (48) Enclave attributes */
    sgx_attributes_t attributes;

    /* (64) Enclave measurement */
    uint8_t mrenclave[OE_SHA256_SIZE];

    /* (96) */
    uint8_t reserved2[32];

    /* (128) The value of the enclave's SIGNER measurement */
    uint8_t mrsigner[OE_SHA256_SIZE];

    /* (160) */
    uint8_t reserved3[96];

    /* (256) Enclave product ID */
    uint16_t isvprodid;

    /* (258) Enclave security version */
    uint16_t isvsvn;

    /* (260) Reserved */
    uint8_t reserved4[60];

    /* (320) User report data */
    sgx_report_data_t report_data;
} sgx_report_body_t;

typedef struct _sgx_report
{
    /* (0) */
    sgx_report_body_t body;

    /* (384) Id of key (?) */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (416) Message authentication code over fields of this structure */
    uint8_t mac[SGX_MAC_SIZE];
} sgx_report_t;

OE_CHECK_SIZE(sizeof(sgx_report_t), 432);

/*
**==============================================================================
**
** sgx_quote_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_quote
{
    /* (0) */
    uint16_t version;

    /* (2) */
    uint16_t sign_type;

    /* (4) */
    uint8_t reserved[4];

    /* (8) */
    uint16_t qe_svn;

    /* (10) */
    uint16_t pce_svn;

    /* (12) */
    uint8_t uuid[16];

    /* (28) */
    uint8_t user_data[20];

    /* (48) */
    sgx_report_body_t report_body;

    /* (432) */
    uint32_t signature_len;

    /* (436) signature array (varying length) */
    OE_ZERO_SIZED_ARRAY uint8_t signature[];
} sgx_quote_t;
OE_PACK_END

OE_CHECK_SIZE(sizeof(sgx_quote_t), 436);

// Size of actual data within the quote excluding authentication information.
// This data is signed for quote verification.
#define SGX_QUOTE_SIGNED_DATA_SIZE OE_OFFSETOF(sgx_quote_t, signature_len)

/*
**==============================================================================
**
** sgx_ecdsa256_signature_t
**
**==============================================================================
*/

typedef struct _sgx_ecdsa256_signature
{
    uint8_t r[32];
    uint8_t s[32];
} sgx_ecdsa256_signature_t;

OE_CHECK_SIZE(sizeof(sgx_ecdsa256_signature_t), 64);

/*
**==============================================================================
**
** sgx_ecdsa256_key_t
**
**==============================================================================
*/

typedef struct _sgx_ecdsa256_key
{
    uint8_t x[32];
    uint8_t y[32];
} sgx_ecdsa256_key_t;

OE_CHECK_SIZE(sizeof(sgx_ecdsa256_key_t), 64);

/*
**==============================================================================
**
** sgx_quote_auth_data_t
**
**==============================================================================
*/

typedef struct _sgx_quote_auth_data
{
    /* (0) Pair of 256 bit ECDSA Signature. */
    sgx_ecdsa256_signature_t signature;

    /* (64) Pair of 256 bit ECDSA Key. */
    sgx_ecdsa256_key_t attestation_key;

    /* (128) Quoting Enclave Report Body */
    sgx_report_body_t qe_report_body;

    /* (512) Quoting Enclave Report Body Signature */
    sgx_ecdsa256_signature_t qe_report_body_signature;
} sgx_quote_auth_data_t;

OE_STATIC_ASSERT(OE_OFFSETOF(sgx_quote_auth_data_t, signature) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(sgx_quote_auth_data_t, attestation_key) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(sgx_quote_auth_data_t, qe_report_body) == 128);
OE_STATIC_ASSERT(
    OE_OFFSETOF(sgx_quote_auth_data_t, qe_report_body_signature) == 512);
OE_STATIC_ASSERT(sizeof(sgx_quote_auth_data_t) == 576);

/*
**==============================================================================
**
** sgx_qe_auth_data_t
**
**==============================================================================
*/

typedef struct _sgx_qe_auth_data
{
    uint16_t size;
    uint8_t* data;
} sgx_qe_auth_data_t;

/*
**==============================================================================
**
** sgx_qe_cert_data_t
**
**==============================================================================
*/

typedef struct _sgx_qe_cert_data
{
    uint16_t type;
    uint32_t size;
    uint8_t* data;
} sgx_qe_cert_data_t;

/*
**==============================================================================
**
** oe_sgx_pckid_t
**
**==============================================================================
*/
typedef enum _oe_sgx_pckid
{
    OE_SGX_PCK_ID_PLAIN_PPID = 1,
    OE_SGX_PCK_ID_ENCRYPTED_PPID_2048 = 2,
    OE_SGX_PCK_ID_ENCRYPTED_PPID_3072 = 3,
    OE_SGX_PCK_ID_PCK_CERTIFICATE = 4,
    OE_SGX_PCK_ID_PCK_CERT_CHAIN = 5,
    __OE_SGX_PCKID_MAX = OE_ENUM_MAX
} oe_sgx_pckid_t;

OE_STATIC_ASSERT(sizeof(oe_sgx_pckid_t) == sizeof(unsigned int));

#define OE_SGX_QUOTE_VERSION (3)

/*
**==============================================================================
**
** sgx_sig_rl_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_sig_rl
{
    /* big-endian */
    uint16_t protocol_version;

    /* big-endian (14 for sig_rl) */
    uint16_t epid_identifier;

    /* Signature revocation list implementation */
    sgx_epid_sig_rl_t sig_rl;

} sgx_sig_rl_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_wrap_key_t
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_wrap_key
{
    uint8_t encrypted_key[256];
    uint8_t key_hash[32];
} sgx_wrap_key_t;
OE_PACK_END

/*
**==============================================================================
**
** sgx_quote_type_t
**
**==============================================================================
*/

typedef enum _sgx_quote_type
{
    SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
    SGX_QUOTE_TYPE_LINKABLE_SIGNATURE,
    __SGX_QUOTE_TYPE_MAX = OE_ENUM_MAX,
} sgx_quote_type_t;

OE_STATIC_ASSERT(sizeof(sgx_quote_type_t) == sizeof(unsigned int));

/*
**==============================================================================
**
** sgx_spid_t
**
**==============================================================================
*/

typedef struct _sgx_spid
{
    uint8_t id[16];
} sgx_spid_t;

/*
**==============================================================================
**
** sgx_nonce_t
**
**==============================================================================
*/

typedef struct _sgx_nonce
{
    uint8_t rand[16];
} sgx_nonce_t;

/*
**==============================================================================
**
** sgx_init_quote()
**
**==============================================================================
*/

oe_result_t sgx_init_quote(
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* epid_group_id);

/*
**==============================================================================
**
** sgx_quote_signature_t
**
**     Layout of signature obtained with sgx_get_quote operation
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _sgx_quote_signature
{
    /* (0) */
    sgx_wrap_key_t wrap_key;

    /* (288) */
    uint8_t iv[SGX_QUOTE_IV_SIZE];

    /* (300) */
    uint32_t payload_size;

    /* (304) encrypted field */
    sgx_epid_basic_signature_t basic_signature;

    /* (656) encrypted field */
    uint32_t rl_ver;

    /* (660) encrypted field */
    uint32_t rl_num;

    /* (664) encrypted NRP followed by MAC */
    OE_ZERO_SIZED_ARRAY uint8_t nrp_mac[];
} sgx_quote_signature_t;
OE_PACK_END

OE_STATIC_ASSERT(sizeof(sgx_quote_signature_t) == 664);

/*
**==============================================================================
**
** SGX key-related definitions
** Refer to KEY REQUEST (KEYREQUEST) in Intel SDM.
**
**==============================================================================
*/

/* Key name. */
#define SGX_KEYSELECT_EINITTOKEN 0x0000
#define SGX_KEYSELECT_PROVISION 0x0001
#define SGX_KEYSELECT_PROVISION_SEAL 0x0002
#define SGX_KEYSELECT_REPORT 0x0003
#define SGX_KEYSELECT_SEAL 0x0004

/* Key policy. */
#define SGX_KEYPOLICY_MRENCLAVE 0x0001
#define SGX_KEYPOLICY_MRSIGNER 0x0002
#define SGX_KEYPOLICY_ALL (SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)

OE_PACK_BEGIN
typedef struct _sgx_key_request
{
    /* (0) Identifies the Key Required. */
    uint16_t key_name;

    /* (2) Identifies which inputs are required to be used in the key derivation
    .*/
    uint16_t key_policy;

    /* (4) The ISV security version number that will be used in the key
    derivation.*/
    uint16_t isv_svn;

    /* (6) Must be zero.*/
    uint16_t reserved1;

    /* (8) The security version number of the processor used in the key
    derivation.*/
    uint8_t cpu_svn[SGX_CPUSVN_SIZE];

    /* (24) A mask defining which SECS.ATTRIBUTES bits will be included in key
    derivation*/
    sgx_attributes_t attribute_mask;

    /* (40) Value for key wear-out protection. */
    uint8_t key_id[SGX_KEYID_SIZE];

    /* (72) A mask defining which MISCSELECT bits will be included in key
    derivation.*/
    uint32_t misc_attribute_mask;

    /* (76) Identifies which enclave Configuration's Security Version should be
    used in key derivation.*/
    uint16_t config_svn;

    /* (78) Must be zero.*/
    uint8_t reserved2[434];
} sgx_key_request_t;
OE_PACK_END

OE_STATIC_ASSERT(sizeof(sgx_key_request_t) == 512);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, key_name), 0);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, key_policy), 2);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, isv_svn), 4);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, reserved1), 6);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, cpu_svn), 8);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, attribute_mask), 24);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, key_id), 40);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, misc_attribute_mask), 72);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, config_svn), 76);
OE_CHECK_SIZE(OE_OFFSETOF(sgx_key_request_t, reserved2), 78);

/* Refer to EGETKEY leaf instruction in Intel SDM. */
/* EGETKEY instruction return values. */
#define SGX_EGETKEY_SUCCESS 0
#define SGX_EGETKEY_INVALID_ATTRIBUTE (1 << (1))
#define SGX_EGETKEY_INVALID_CPUSVN (1 << (5))
#define SGX_EGETKEY_INVALID_ISVSVN (1 << (6))
#define SGX_EGETKEY_INVALID_KEYNAME (1 << (8))

/* Alignment requirement. */
#define SGX_KEY_REQUEST_ALIGNMENT 512
#define SGX_KEY_ALIGNMENT 16

/* The 128-bit SGX secret key. */
typedef struct _sgx_key
{
    uint8_t buf[16];
} sgx_key_t;

/* Enclave Flags Bit Masks */
/* If set, then the enclave is initialized */
#define SGX_FLAGS_INITTED 0x0000000000000001ULL
/* If set, then the enclave is debug */
#define SGX_FLAGS_DEBUG 0x0000000000000002ULL
/* If set, then the enclave is 64 bit */
#define SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
/* If set, then the enclave has access to provision key */
#define SGX_FLAGS_PROVISION_KEY 0x0000000000000010ULL
/* If set, then the enclave has access to EINITTOKEN key */
#define SGX_FLAGS_EINITTOKEN_KEY 0x0000000000000020ULL
#define SGX_FLAGS_RESERVED                                         \
    (~(SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT | \
       SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_EINITTOKEN_KEY))

/* Set the bits which have no security implications to 0 for sealed data
 migration */
/* Bits which have no security implications in attributes.flags:
 *    Reserved bit[55:6]  - 0xFFFFFFFFFFFFC0ULL
 *    SGX_FLAGS_MODE64BIT
 *    SGX_FLAGS_PROVISION_KEY
 *    SGX_FLAGS_EINITTOKEN_KEY */
#define SGX_FLAGS_NON_SECURITY_BITS                                        \
    (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY | \
     SGX_FLAGS_EINITTOKEN_KEY)

/* bit[27:0]: have no security implications */
#define SGX_MISC_NON_SECURITY_BITS 0x0FFFFFFFU

/* OE seal key default flag masks*/
#define OE_SEALKEY_DEFAULT_FLAGSMASK (~SGX_FLAGS_NON_SECURITY_BITS)
#define OE_SEALKEY_DEFAULT_MISCMASK (~SGX_MISC_NON_SECURITY_BITS)
#define OE_SEALKEY_DEFAULT_XFRMMASK (0X0ULL)

OE_EXTERNC_END

#endif /* _OE_SGXTYPES_H */
