// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/datetime.h>

OE_EXTERNC_BEGIN

#define OE_TCB_LEVEL_STATUS_UNKNOWN (0)
// Info should be of type oe_parsed_tcb_info_t, field should be one of common
// fields among oe_parsed_tcb_info_v2_t and oe_parsed_tcb_info_v3_t Valid fields
// are: version, issue_date, next_update, fmspc, pceid, tcb_type,
// tcb_evaluation_data_number If version is not 3, defaults to return v2 (which
// also handles v1)
#define OE_TCB_INFO_GET(info, field)                  \
    ((info)->version == 3 ? (info)->tcb_info_v3.field \
                          : (info)->tcb_info_v2.field)

/*! \struct oe_tcb_level_status_t
 */
typedef union _oe_tcb_level_status
{
    struct
    {
        uint32_t revoked : 1;              //! "Revoked"
        uint32_t outofdate : 1;            //! "OutOfDate"
        uint32_t configuration_needed : 1; //! "ConfigurationNeeded"
        uint32_t up_to_date : 1;           //! "UpToDate"
        uint32_t qe_identity_out_of_date : 1;
        uint32_t sw_hardening_needed : 1; //! "SWHardeningNeeded"
    } fields;
    uint32_t AsUINT32;

} oe_tcb_level_status_t;

#define OE_TDX_MRSIGNER_SIZE 48
#define OE_TDX_ATTR_SIZE 8

/*! \struct oe_tcb_info_tdx_module_t
 *  \brief TDX Module info in the TCB Info V3.
 */
typedef struct _oe_tcb_info_tdx_module
{
    // Base 16-encoded string representation of the measurement of a TDX SEAM
    // module’s signer
    uint8_t mrsigner[OE_TDX_MRSIGNER_SIZE];

    // Hex-encoded byte array (8 bytes) representing attributes "golden" value.
    uint8_t attributes[OE_TDX_ATTR_SIZE];

    // Hex-encoded byte array (8 bytes) representing mask
    // to be applied to TDX SEAM module’s attributes value retrieved from the
    // platform.
    uint8_t attributes_mask[OE_TDX_ATTR_SIZE];
} oe_tcb_info_tdx_module_t;

#define OE_TCB_COMPONENT_SIZE 16

/*! \struct oe_tcb_info_tcb_level_t
 *  \brief TCB level field in the SGX TCB Info.
 *
 *  Version 2 of the SGX endorsements/collaterals, the QE Identiy
 *  Info structure also has a TCB level field (\ref See oe_qe_info_tcb_level_t).
 */
typedef struct _oe_tcb_info_tcb_level
{
    uint8_t sgx_tcb_comp_svn[OE_TCB_COMPONENT_SIZE];
    uint16_t pce_svn;
    oe_tcb_level_status_t status;

    // V2, V3 fields
    oe_datetime_t tcb_date;

    // V3 fields
    uint8_t tdx_tcb_comp_svn[OE_TCB_COMPONENT_SIZE];

    /*! Offset into the json QE Identity info where
     * the advisoryIDs fields start.
     */
    size_t advisory_ids_offset;

    //! Total size of all the advisoryIDs.
    size_t advisory_ids_size;
} oe_tcb_info_tcb_level_t;

#define OE_SGX_FMSPC_SIZE 6
#define OE_SGX_PCEID_SIZE 2

/*! \struct oe_parsed_tcb_info_v2_t
 *  \brief TCB info excluding the TCB levels field.
 */
typedef struct _oe_parsed_tcb_info_v2
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint8_t fmspc[OE_SGX_FMSPC_SIZE];
    uint8_t pceid[OE_SGX_PCEID_SIZE];

    uint32_t tcb_type;
    uint32_t tcb_evaluation_data_number;
    oe_tcb_info_tcb_level_t tcb_level;

} oe_parsed_tcb_info_v2_t;

#define OE_TCB_ID_SIZE 4

/*! \struct oe_parsed_tcb_info_v3_t
 *  \brief TCB info excluding the TCB levels field.
 */
typedef struct _oe_parsed_tcb_info_v3
{
    uint8_t id[OE_TCB_ID_SIZE];
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint8_t fmspc[OE_SGX_FMSPC_SIZE];
    uint8_t pceid[OE_SGX_PCEID_SIZE];

    uint32_t tcb_type;
    uint32_t tcb_evaluation_data_number;
    oe_tcb_info_tdx_module_t tdx_module;
    oe_tcb_info_tcb_level_t tcb_level;
} oe_parsed_tcb_info_v3_t;

typedef struct _oe_parsed_tcb_info
{
    uint32_t version;
    uint8_t signature[64];
    union
    {
        oe_parsed_tcb_info_v2_t tcb_info_v2;
        oe_parsed_tcb_info_v3_t tcb_info_v3;
    };

    const uint8_t* tcb_info_start;
    size_t tcb_info_size;
} oe_parsed_tcb_info_t;

/*!
 * Parse an oe_tcb_info_tcb_level_t struct to an oe_sgx_tcb_status_t type.
 *
 * @param[in] tcb_level_status The tcb_status to parse.
 */
oe_sgx_tcb_status_t oe_tcb_level_status_to_sgx_tcb_status(
    oe_tcb_level_status_t tcb_level_status);

/*!
 * Retrieve a string description for an oe_sgx_tcb_status_t code.
 *
 * @param[in] sgx_tcb_status Retrieve string description for this SGX TCB status
 * code.
 *
 * @returns Returns a pointer to a static string description.
 *
 */
const char* oe_sgx_tcb_status_str(const oe_sgx_tcb_status_t sgx_tcb_status);

/**
 * oe_parse_tcb_info_json parses the given tcb info json string
 * and populates the parsed_info structure.
 * Additionally, the status field of the platform_tcb_level parameter is
 * populated.
 *
 * The TCB info is expected to confirm to the TCB Info Json schema published by
 * Intel. For the given platform_tcb_level, the correct status is determined
 * using the following algorithm:
 *
 *    1. Go over the sorted collection of TCB levels in the JSON.
 *    2. Choose the first tcb level for which  all of the platform's comp svn
 *       values and pcesvn values are greater than or equal to corresponding
 *       values of the tcb level.
 *    3. The status of the platform's tcb level is the status of the chosen tcb
 *       level.
 *    4. If no tcb level was chosen, then the status of the platform is unknown.
 *
 * If the plaform's tcb level status was determined to be not uptodate,
 * then OE_TCB_LEVEL_INVALID is returned.
 *
 * @param[in] tcb_info_json The json string to parse.
 * @param[in] tcb_info_json_size The string length of info_json
 * @param[in] platform_tcb_level The platform tcb level.
 *                The sgx_tcb_comp_svn and pce_svn fields are required to be
 * set.
 * @param[out] parsed_info The parsed results.
 */
oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    size_t tcb_info_json_size,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info);

oe_result_t oe_verify_ecdsa256_signature(
    const uint8_t* tcb_info_start,
    size_t tcb_info_size,
    sgx_ecdsa256_signature_t* signature,
    oe_cert_chain_t* tcb_cert_chain);

/*! \enum oe_qe_identity_id
 *  \brief Quoting enclave identity id (V2 only)
 */
typedef enum _oe_qe_identity_id
{
    QE_IDENTITY_ID_QE,
    QE_IDENTITY_ID_QVE
} oe_qe_identity_id_t;

/*! \struct oe_qe_tcb_level
 *  \brief Quoting enclave identity TCB level.  Applies to V2 only.
 */
typedef struct _oe_qe_identity_info_tcb_level
{
    uint32_t isvsvn[1];
    oe_tcb_level_status_t tcb_status;
    oe_datetime_t tcb_date;

    /*! Offset into the json QE Identity info where
     * the advisoryIDs fields start.
     */
    size_t advisory_ids_offset;

    //! Total size of all the advisoryIDs.
    size_t advisory_ids_size;
} oe_qe_identity_info_tcb_level_t;

/*! \struct oe_parsed_qe_identity_info_t
 *  \brief SGX Quoting Enclave Identity Info data structure.
 */
typedef struct _oe_parsed_qe_identity_info
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint32_t miscselect;         //! The MISCSELECT that must be set
    uint32_t miscselect_mask;    //! Mask of MISCSELECT to enforce
    sgx_attributes_t attributes; //! flags and xfrm (XSAVE-Feature Request Mask)
    uint64_t attributes_flags_mask;   //! mask for attributes.flags
    uint64_t attributes_xfrm_mask;    //! mask for attributes.xfrm
    uint8_t mrsigner[OE_SHA256_SIZE]; //! MRSIGNER of the enclave
    uint16_t isvprodid;               //! ISV assigned Product ID
    uint16_t isvsvn;                  //! ISV assigned SVN
    uint8_t signature[64];

    // V2 fields
    oe_qe_identity_id_t id;
    uint32_t tcb_evaluation_data_number;
    oe_qe_identity_info_tcb_level_t tcb_level;

    const uint8_t* info_start;
    size_t info_size;
} oe_parsed_qe_identity_info_t;

/*!
 * Parse a QE or QVE identity json string.
 *
 * @param[in] info_json The json string to parse.
 * @param[in] info_json_size The string length of info_json
 * @param[in,out] platform_tcb_level The platform tcb level.
 *                The platform isvsvn is required to be set as input.
 *                The status field is updated as output.
 * @param[out] parsed_info The parsed results.
 */
oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_qe_identity_info_tcb_level_t* platform_tcb_level,
    oe_parsed_qe_identity_info_t* parsed_info);

/*!
 * Parse an advisoryIDs field json string.
 *
 * @param[in] json Json string to parse.
 * @param[in] json_size Length of the json string.
 * @param[out] id_array Array of char* to store the resulting advisoryIDs.
 * @param[in] json_size The number of elements in array id_array.
 * @param[out] id_sizes_array Array of the length of each id in id_array.
 * @param[in] id_sizes_size The number of elements in array id_sizes_array.
 * @param[out] num_ids The number of advisoryIDs set in id_array.
 */
oe_result_t oe_parse_advisoryids_json(
    const uint8_t* json,
    size_t json_size,
    const uint8_t** id_array,
    size_t id_array_size,
    size_t* id_sizes_array,
    size_t id_sizes_size,
    size_t* num_ids);

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
