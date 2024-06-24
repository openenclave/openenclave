// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TDX_VERIFIER_H
#define _OE_COMMON_TDX_VERIFIER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef int64_t time_t;

/* This file needs to be synchronized with Intel SGX SDK */

/* The following definition is based on sgx_key.h from Intel SGX SDK */

#define SGX_CPUSVN_SIZE 16

typedef uint8_t sgx_key_128bit_t[16];
typedef uint16_t sgx_isv_svn_t;

typedef struct _sgx_cpu_svn_t
{
    uint8_t svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

/* The following definition is based on sgx_qve_header.h from Intel SGX SDK
 * Version 1.20
 * https://github.com/intel/SGXDataCenterAttestationPrimitives/releases/tag/DCAP_1.20
 */

#ifndef SGX_QL_QV_MK_ERROR
#define SGX_QL_QV_MK_ERROR(x) (0x0000A000 | (x))
#endif // SGX_QL_QV_MK_ERROR

/** Contains the possible values of the quote verification result. */
typedef enum _sgx_ql_qv_result_t
{
    SGX_QL_QV_RESULT_OK = 0x0000, ///< The Quote verification passed and is at
                                  ///< the latest TCB level
    SGX_QL_QV_RESULT_MIN = SGX_QL_QV_MK_ERROR(0x0001),
    SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(
        0x0001), ///< The Quote verification passed and the platform is patched
                 ///< to the latest TCB level but additional configuration of
                 ///< the SGX platform may be needed
    SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(
        0x0002), ///< The Quote is good but TCB level of the platform is out of
                 ///< date. The platform needs patching to be at the latest TCB
                 ///< level
    SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(
        0x0003), ///< The Quote is good but the TCB level of the platform is out
                 ///< of date and additional configuration of the SGX Platform
                 ///< at its current patching level may be needed. The platform
                 ///< needs patching to be at the latest TCB level
    SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(
        0x0004), ///< The signature over the application report is invalid
    SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(
        0x0005), ///< The attestation key or platform has been revoked
    SGX_QL_QV_RESULT_UNSPECIFIED =
        SGX_QL_QV_MK_ERROR(0x0006), ///< The Quote verification failed due to an
                                    ///< error in one of the input
    SGX_QL_QV_RESULT_SW_HARDENING_NEEDED =
        SGX_QL_QV_MK_ERROR(0x0007), ///< The TCB level of the platform is up to
                                    ///< date, but SGX SW Hardening is needed
    SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(
        0x0008), ///< The TCB level of the platform is up to date, but
                 ///< additional configuration of the platform at its current
                 ///< patching level may be needed. Moreove, SGX SW Hardening is
                 ///< also needed
    SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED = SGX_QL_QV_MK_ERROR(
        0x0009), ///< For TDX only. All components in the TD’s TCB are latest,
                 ///< including the TD preserving loaded TDX, but the TD was
                 ///< launched and ran for some time with out-of-date TDX
                 ///< Module. Relaunching or re-provisioning your TD is advised
    SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED =
        SGX_QL_QV_MK_ERROR(0x0010), /// Upcoming change in Intel DCAP 1.21,
                                    /// manually added, error code could change
    SGX_QL_QV_RESULT_MAX = SGX_QL_QV_MK_ERROR(
        0x00FF), ///< Indicate max result to allow better translation

} sgx_ql_qv_result_t;

typedef enum _pck_cert_flag_enum_t
{
    PCK_FLAG_FALSE = 0,
    PCK_FLAG_TRUE,
    PCK_FLAG_UNDEFINED
} pck_cert_flag_enum_t;

#define ROOT_KEY_ID_SIZE 48
#define PLATFORM_INSTANCE_ID_SIZE 16

// Each Intel Advisory size is ~16 bytes
// Assume each TCB level has 20 advisoryIDs at the very most
#define MAX_SA_LIST_SIZE 320

// Nameless struct generates C4201 warning in MS compiler, but it is allowed in
// c++ 11 standard Should remove the pragma after Microsoft fixes this issue
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4201)
#endif

/** Contains data that will allow an alternative quote verification policy. */
typedef struct _sgx_ql_qv_supplemental_t
{
    union
    {
        uint32_t version; ///< 'version' is the backward compatible legacy
                          ///< representation
        struct
        {
            uint16_t
                major_version; ///< If this major version doesn't change, the
                               ///< size of the structure may change and new
                               ///< fields appended to the end but old minor
                               ///< version structure can still be 'cast' If
                               ///< this major version does change, then the
                               ///< structure has been modified in a way that
                               ///< makes the older definitions non-backwards
                               ///< compatible. i.e. You cannot 'cast' older
                               ///< definitions
            uint16_t
                minor_version; ///< If this version changes, new fields have
                               ///< been appended to the end of the previous
                               ///< minor version definition of the structure
                               ///< Set to 1 to support SA_List.  Set to 0 to
                               ///< support everything except the SA List
        };
    };
    time_t earliest_issue_date; ///< Earliest issue date of all the collateral
                                ///< (UTC)
    time_t latest_issue_date; ///< Latest issue date of all the collateral (UTC)
    time_t earliest_expiration_date; ///< Earliest expiration date of all the
                                     ///< collateral (UTC)
    time_t tcb_level_date_tag; ///< The SGX TCB of the platform that generated
                               ///< the quote is not vulnerable to any Security
                               ///< Advisory with an SGX TCB impact released on
                               ///< or before this date. See Intel Security
                               ///< Center Advisories
    uint32_t pck_crl_num;      ///< CRL Num from PCK Cert CRL
    uint32_t root_ca_crl_num;  ///< CRL Num from Root CA CRL
    uint32_t tcb_eval_ref_num; ///< Lower number of the TCBInfo and QEIdentity
    uint8_t root_key_id[ROOT_KEY_ID_SIZE]; ///< ID of the collateral's root
                                           ///< signer (hash of Root CA's public
                                           ///< key SHA-384)
    sgx_key_128bit_t pck_ppid; ///< PPID from remote platform.  Can be used for
                               ///< platform ownership checks
    sgx_cpu_svn_t tcb_cpusvn;  ///< CPUSVN of the remote platform's PCK Cert
    sgx_isv_svn_t
        tcb_pce_isvsvn; ///< PCE_ISVNSVN of the remote platform's PCK Cert
    uint16_t pce_id;    ///< PCE_ID of the remote platform
    uint32_t tee_type;  ///< 0x00000000: SGX or 0x00000081: TDX
    uint8_t sgx_type;   ///< Indicate the type of memory protection available on
                        ///< the platform, it should be one of Standard (0),
                        ///< Scalable (1) and Scalable with Integrity (2)

    // Multi-Package PCK cert related flags, they are only relevant to PCK
    // Certificates issued by PCK Platform CA
    uint8_t
        platform_instance_id[PLATFORM_INSTANCE_ID_SIZE]; ///< Value of Platform
                                                         ///< Instance ID, 16
                                                         ///< bytes
    pck_cert_flag_enum_t
        dynamic_platform; ///< Indicate whether a platform can be extended with
                          ///< additional packages - via Package Add calls to
                          ///< SGX Registration Backend
    pck_cert_flag_enum_t
        cached_keys; ///< Indicate whether platform root keys are cached by SGX
                     ///< Registration Backend
    pck_cert_flag_enum_t smt_enabled; ///< Indicate whether a plat form has SMT
                                      ///< (simultaneous multithreading) enabled

    char sa_list[MAX_SA_LIST_SIZE];     ///< String of comma separated list of
                                        ///< Security Advisory IDs
    time_t qe_iden_earliest_issue_date; ///< Earliest issue date of QEIdentity
                                        ///< (UTC)
    time_t qe_iden_latest_issue_date; ///< Latest issue date of QEIdentity (UTC)
    time_t qe_iden_earliest_expiration_date; ///< Earliest expiration date of
                                             ///< QEIdentity (UTC)
    time_t
        qe_iden_tcb_level_date_tag; ///< The SGX TCB of the platform that
                                    ///< generated the quote is not vulnerable
    uint32_t qe_iden_tcb_eval_ref_num; ///< Lower number of the QEIdentity
    sgx_ql_qv_result_t qe_iden_status; /// QEIdentity status
} sgx_ql_qv_supplemental_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

OE_EXTERNC_END

#endif // _OE_COMMON_TDX_VERIFIER_H
