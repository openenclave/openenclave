// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXTYPES_H
#define _OE_SGXTYPES_H

#include <openenclave/bits/sha.h>
#include <openenclave/defs.h>
#include <openenclave/properties.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "epid.h"
#include "jump.h"
#include "load.h"

OE_EXTERNC_BEGIN

#define OE_KEY_SIZE 384
#define OE_EXPONENT_SIZE 4

#define SGX_FLAGS_INITTED 0x0000000000000001ULL
#define SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define SGX_FLAGS_PROVISION_KEY 0x0000000000000010ULL
#define SGX_FLAGS_EINITTOKEN_KEY 0x0000000000000020ULL

#define SGX_XFRM_LEGACY 0x0000000000000003ULL
#define SGX_XFRM_AVX 0x0000000000000006ULL
#define SGX_XFRM_AVX512 0x00000000000000E6ULL
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

OE_STATIC_ASSERT(SGX_FLAGS_DEBUG == OE_SGX_FLAGS_DEBUG);
OE_STATIC_ASSERT(SGX_FLAGS_MODE64BIT == OE_SGX_FLAGS_MODE64BIT);

/* Rename OE_? types to SGX_? to make SGX types more explicit */

/*
**==============================================================================
**
** SGX Instructions:
**
**==============================================================================
*/

#define ENCLU_INSTRUCTION 0xd7010f

typedef enum _SGX_ENCLULeaf {
    ENCLU_EREPORT = 0x00,
    ENCLU_EGETKEY = 0x01,
    ENCLU_EENTER = 0x02,
    ENCLU_ERESUME = 0x03,
    ENCLU_EEXIT = 0x04,
    ENCLU_EACCEPT = 0x05,
    ENCLU_EMODPE = 0x06,
    ENCLU_EACCEPTCOPY = 0x07,
} SGX_ENCLULeaf;

/*
**==============================================================================
**
** SGX_Attributes:
**
**==============================================================================
*/

/* Default value for SGX_Attributes.flags */
#define SGX_ATTRIBUTES_DEFAULT_FLAGS 0x0000000000000006

/* Default value for SGX_Attributes.xfrm */
#define SGX_ATTRIBUTES_DEFAULT_XFRM 0x0000000000000007

OE_PACK_BEGIN
typedef struct _SGX_Attributes
{
    uint64_t flags;
    uint64_t xfrm;
} SGX_Attributes;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_Attributes), 16);

/*
**==============================================================================
**
** SGX_SigStruct
**
**==============================================================================
*/

/* SGX_SigStruct.header: 06000000E100000000000100H */
#define SGX_SIGSTRUCT_HEADER "\006\000\000\000\341\000\000\000\000\000\001\000"
#define SGX_SIGSTRUCT_HEADER_SIZE (sizeof(SGX_SIGSTRUCT_HEADER) - 1)

/* SGX_SigStruct.header2: 01010000600000006000000001000000H */
#define SGX_SIGSTRUCT_HEADER2 \
    "\001\001\000\000\140\000\000\000\140\000\000\000\001\000\000\000"
#define SGX_SIGSTRUCT_HEADER2_SIZE (sizeof(SGX_SIGSTRUCT_HEADER2) - 1)

/* SGX_SigStruct.miscselect */
#define SGX_SIGSTRUCT_MISCSELECT 0x00000000

/* SGX_SigStruct.miscmask */
#define SGX_SIGSTRUCT_MISCMASK 0xffffffff

/* SGX_SigStruct.flags */
#define SGX_SIGSTRUCT_ATTRIBUTEMASK_FLAGS 0Xfffffffffffffffb

/* SGX_SigStruct.xfrm */
#define SGX_SIGSTRUCT_ATTRIBUTEMASK_XFRM 0x0000000000000000

/* 1808 bytes */
OE_PACK_BEGIN
typedef struct _SGX_SigStruct
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
    SGX_Attributes attributes;

    /* (944) Mask of Attributes to Enforce */
    SGX_Attributes attributemask;

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
} SGX_SigStruct;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_SigStruct), 1808);
OE_CHECK_SIZE(sizeof(SGX_SigStruct), OE_SGX_SIGSTRUCT_SIZE);

OE_CHECK_SIZE(sizeof((SGX_SigStruct*)NULL)->header, SGX_SIGSTRUCT_HEADER_SIZE);

OE_CHECK_SIZE(
    sizeof((SGX_SigStruct*)NULL)->header2,
    SGX_SIGSTRUCT_HEADER2_SIZE);

OE_INLINE const void* SGX_SigStructHeader(const SGX_SigStruct* ss)
{
    return ss;
}

OE_INLINE size_t SGX_SigStructHeaderSize(void)
{
    return OE_OFFSETOF(SGX_SigStruct, modulus);
}

OE_INLINE const void* SGX_SigStructBody(const SGX_SigStruct* ss)
{
    return &ss->miscselect;
}

OE_INLINE size_t SGX_SigStructBodySize(void)
{
    return OE_OFFSETOF(SGX_SigStruct, reserved4) -
           OE_OFFSETOF(SGX_SigStruct, miscselect);
}

void __SGX_DumpSigStruct(const SGX_SigStruct* p);

/*
**==============================================================================
**
** SGX_Secs:
**
**==============================================================================
*/

typedef struct _SGX_Secs
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
} SGX_Secs;

OE_CHECK_SIZE(sizeof(SGX_Secs), 4096);

/*
**==============================================================================
**
** SGX_ExitInfo:
**
**==============================================================================
*/

typedef union {
    struct
    {
        uint32_t vector : 8;
        uint32_t exitType : 3;
        uint32_t mbz : 20;
        uint32_t valid : 1;
    } asFields;
    uint32_t asUINT32;
} SGX_ExitInfo;

/*
**==============================================================================
**
** SGX_SsaGpr:
**
**==============================================================================
*/

typedef struct SGX_SsaGpr
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
    SGX_ExitInfo exitInfo;
    uint32_t reserved;
    uint64_t fSBase;
    uint64_t gSBase;
} SGX_SsaGpr, *PSGX_SsaGpr;

/*
**==============================================================================
**
** SGX_LaunchToken
**
**==============================================================================
*/

typedef struct _SGX_LaunchToken
{
    unsigned char contents[1024];
} SGX_LaunchToken;

/*
**==============================================================================
**
** SGX_EInitToken
**
**==============================================================================
*/

#define SGX_CPUSVN_SIZE 16
#define SGX_KEYID_SIZE 32
#define SGX_MAC_SIZE 16

OE_PACK_BEGIN
typedef struct _SGX_EInitToken
{
    /* (0) 0=invalid, 1=valid */
    uint32_t valid;

    /* (4) must be zero */
    uint8_t reserved1[44];

    /* (48) attributes of the enclave */
    SGX_Attributes attributes;

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
    SGX_Attributes maskedattributesle;

    /* (256) value for key wear-out protection */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (288) CMAC using Launch Token Key */
    uint8_t mac[SGX_MAC_SIZE];
} SGX_EInitToken;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_EInitToken), 304);

void __SGX_DumpEinitToken(const SGX_EInitToken* p);

/*
**==============================================================================
**
** SGX_TCS
**
**==============================================================================
*/

typedef struct _SGX_TCS
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

        /* (72) Enclave's OE_Main() function */
        void (*main)(void);
    } u;
} SGX_TCS;

OE_CHECK_SIZE(sizeof(SGX_TCS), 4096);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, state), 0);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, flags), 8);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, ossa), 16);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, cssa), 24);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, nssa), 28);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, oentry), 32);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, aep), 40);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, fsbase), 48);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, gsbase), 56);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, fslimit), 64);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, gslimit), 68);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, u.reserved), 72);
OE_CHECK_SIZE(OE_OFFSETOF(SGX_TCS, u.main), 72);

/*
**==============================================================================
**
** OE_ThreadData
**
**     This structure defines information about an enclave thread. Each
**     instance is associated with one thread control structure (TCS). This
**     structure resides in the GS segment page (referenced by the GS segment
**     register). A thread obtains its thread data structure by calling
**     OE_GetThreadData(), which fetches the address at offset zero in
**     the GS segment register (%gs:0) which contains OE_ThreadData.self_addr.
**
**==============================================================================
*/

typedef struct _OE_ThreadData OE_ThreadData;

/* Note: unsued fields have a "__" prefix */
struct _OE_ThreadData
{
    /* Points to start of this structure */
    uint64_t self_addr;

    /* The last stack pointer (set by enclave when making an OCALL) */
    uint64_t last_sp;

    uint64_t __stack_base_addr;
    uint64_t __stack_limit_addr;
    uint64_t __first_ssa_gpr;
    uint64_t __stack_guard; /* 0x28 for x64 */
    uint64_t __reserved_0;
    uint64_t __ssa_frame_size;
    uint64_t __last_error;

    /* The threads implementations uses this to put threads on queues */
    OE_ThreadData* next;

    uint64_t __tls_addr;
    uint64_t __tls_array;
    uint64_t __exception_flag; /* number of exceptions being handled */
    uint64_t __cxx_thread_info[6];

    // The exception code.
    uint32_t exception_code;
    // The exception flags.
    uint32_t exception_flags;
    // The rip when exception happened.
    uint64_t exception_address;
};

OE_CHECK_SIZE(sizeof(OE_ThreadData), 168);

OE_ThreadData* OE_GetThreadData(void);

/*
**==============================================================================
**
** TD
**
**     Extended thread data
**
**==============================================================================
*/

#define TD_MAGIC 0xc90afe906c5d19a3

typedef struct _Callsite Callsite;

typedef struct _TD
{
    OE_ThreadData base;

    /* A "magic number" for sanity checking (TD_MAGIC) */
    uint64_t magic;

    /* Depth of ECALL stack (zero indicates that it is unwound) */
    uint64_t depth;

    /* Host registers saved here on entry and restored on exit */
    uint64_t host_rcx; /* EENTER return address */
    uint64_t host_rsp;
    uint64_t host_rbp;
    uint64_t host_previous_rsp;
    uint64_t host_previous_rbp;

    /* Return arguments from OCALL */
    int64_t oret_func;
    int64_t oret_arg;

    /* List of Callsite structures (most recent call is first) */
    Callsite* callsites;

    /* Simulation mode is active if non-zero */
    uint64_t simulate;

    /* Linux error number: from <errno.h> */
    int linux_errno;

    /* Currently active ocall flags */
    uint32_t ocall_flags;

    /* Reserved */
    uint8_t reserved[3832];
} TD;

OE_CHECK_SIZE(sizeof(TD), 4096);

/*
**==============================================================================
**
** SGX_TargetInfo
**
**==============================================================================
*/

typedef struct _SGX_TargetInfo
{
    /* (0) MRENCLAVE (hash of target enclave) */
    uint8_t mrenclave[OE_SHA256_SIZE];

    /* (32) ATTRIBUTES of target enclave */
    SGX_Attributes attributes;

    /* (48) Reserved */
    uint8_t reserved1[4];

    /* (52) MISCSELECT field of target enclave */
    uint32_t misc_select;

    /* (56) Reserved */
    uint8_t reserved2[456];
} SGX_TargetInfo;

OE_CHECK_SIZE(sizeof(SGX_TargetInfo), 512);

/*
**==============================================================================
**
** SGX_EPIDGroupID
**
**==============================================================================
*/

typedef struct _SGX_EPIDGroupID
{
    uint8_t id[4];
} SGX_EPIDGroupID;

OE_CHECK_SIZE(sizeof(SGX_EPIDGroupID), 4);

/*
**==============================================================================
**
** SGX_ReportData
**
**==============================================================================
*/

typedef struct _SGX_ReportData
{
    unsigned char field[64];
} SGX_ReportData;

OE_CHECK_SIZE(sizeof(SGX_ReportData), 64);

/*
**==============================================================================
**
** SGX_Report
**
**==============================================================================
*/

typedef struct _SGX_ReportBody
{
    /* (0) CPU security version */
    uint8_t cpusvn[SGX_CPUSVN_SIZE];

    /* (16) Selector for which fields are defined in SSA.MISC */
    uint32_t miscselect;

    /* (20) Reserved */
    uint8_t reserved1[28];

    /* (48) Enclave attributes */
    SGX_Attributes attributes;

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
    SGX_ReportData reportData;
} SGX_ReportBody;

typedef struct _SGX_Report
{
    /* (0) */
    SGX_ReportBody body;

    /* (384) Id of key (?) */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (416) Message autentication code over fields of this structure */
    uint8_t mac[SGX_MAC_SIZE];
} SGX_Report;

OE_CHECK_SIZE(sizeof(SGX_Report), 432);

/*
**==============================================================================
**
** SGX_Quote
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_Quote
{
    /* (0) */
    uint16_t version;

    /* (2) */
    uint16_t sign_type;

    /* (4) */
    SGX_EPIDGroupID epid_group_id;

    /* (8) */
    uint16_t qe_svn;

    /* (10) */
    uint16_t pce_svn;

    /* (12) */
    uint32_t xeid;

    /* (16) */
    uint8_t basename[32];

    /* (48) */
    SGX_ReportBody report_body;

    /* (432) */
    uint32_t signature_len;

    /* (436) signature array (varying length) */
    OE_ZERO_SIZED_ARRAY uint8_t signature[];
} SGX_Quote;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_Quote), 436);

/*
**==============================================================================
**
** SGX_SigRL
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_SigRL
{
    /* big-endian */
    uint16_t protocolVersion;

    /* big-endian (14 for sig_rl) */
    uint16_t epidIdentifier;

    /* Signature revocation list implementation */
    SGX_EPID_SigRL sigrl;

} SGX_SigRL;
OE_PACK_END

/*
**==============================================================================
**
** SGX_WrapKey
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_WrapKey
{
    uint8_t encrypted_key[256];
    uint8_t key_hash[32];
} SGX_WrapKey;
OE_PACK_END

/*
**==============================================================================
**
** SGX_QuoteType
**
**==============================================================================
*/

typedef enum _SGX_QuoteType {
    SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
    SGX_QUOTE_TYPE_LINKABLE_SIGNATURE,
} SGX_QuoteType;

/*
**==============================================================================
**
** SGX_SPID
**
**==============================================================================
*/

typedef struct _SGX_SPID
{
    uint8_t id[16];
} SGX_SPID;

/*
**==============================================================================
**
** SGX_Nonce
**
**==============================================================================
*/

typedef struct _SGX_Nonce
{
    uint8_t rand[16];
} SGX_Nonce;

/*
**==============================================================================
**
** OE_ECallPages
**
**     The enclave image has ECALL adddress pages that keep the virtual
**     addresses of all ECALL functions. When the host performs an OCALL, it
**     passes a function number that the enclave uses as an index into this
**     table to obtain the virtual address of the corresponding function.
**
**==============================================================================
*/

#define OE_ECALL_PAGES_MAGIC 0x927ccf78a3de9f9d

typedef struct _OE_ECallPages
{
    /* Should be OE_ECALL_PAGES_MAGIC if page is valid */
    uint64_t magic;

    /* Number of ECALL virtual addresses */
    uint64_t num_vaddrs;

    /* ECALL virtual addresses (index by function number) */
    OE_ZERO_SIZED_ARRAY uint64_t vaddrs[];
} OE_ECallPages;

/*
**==============================================================================
**
** __SGX_InitQuote()
**
**==============================================================================
*/

OE_Result SGX_InitQuote(
    SGX_TargetInfo* targetInfo,
    SGX_EPIDGroupID* epidGroupID);

/*
**==============================================================================
**
** SGX_QuoteSignature
**
**     Layout of signature obtained with SGX_GetQuote operation
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _SGX_QuoteSignature
{
    /* (0) */
    SGX_WrapKey wrap_key;

    /* (288) */
    uint8_t iv[SGX_QUOTE_IV_SIZE];

    /* (300) */
    uint32_t payload_size;

    /* (304) encrypted field */
    SGX_EPID_BasicSignature basic_signature;

    /* (656) encrypted field */
    uint32_t rl_ver;

    /* (660) encrypted field */
    uint32_t rl_num;

    /* (664) encrypted NRP followed by MAC */
    OE_ZERO_SIZED_ARRAY uint8_t nrp_mac[];
} SGX_QuoteSignature;
OE_PACK_END

OE_STATIC_ASSERT(sizeof(SGX_QuoteSignature) == 664);

OE_EXTERNC_END

#endif /* _OE_SGXTYPES_H */
