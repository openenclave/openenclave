SGX Attestation Endorsements V2 Updates
================

Intel SGX released v2 of the Provision Certification Service for ECDSA Attestation.  The
following APIs were affected:

1. Get TCB Info.
2. Get Quoting Enclave Identity.

[API Version 1](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate)

[API Version 2](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v2)

This document describes the changes for supporting version 2 of the API as well as keeping
the existing support for version 1 of the API.  This document assumes the user is familiar with
the SGX attestation endorsements and how it is used during SGX quote verification.

Motivation
----------

This change is required for customers who would like to use the v2 API web endpoints. Note that the Azure PCK
Caching Service and the Azure DCAP Client will also need to be updated and it is outside of the this specification.

User Experience
---------------

The user experience does not change, it should be seamless to the user.  The caller will be able to identify the version of the data by checking the existing `version` field.

The quote verifier will specify whether to use the v1 or v2 Azure PCK Caching Service web API endpoints.  The
quote verification logic will be able to determine the version of the API by checking the `version` field in endorsement data.

Specification
-------------

## Differences between V1 and V2 APIs.

The APIs to get the PCK Certificate and the revocation list are the same between the versions.  The APIs to
get the TCB Info and get QE Identity are different.  The differences are highlighted below.

### Get TCB Info
1. tcbInfo:version changed from 1 to 2.
2. New field tcbInfo:tcbType.
3. New field tcbInfo:tcbEvaluationDataNumber.
4. Field tcbInfo:tcbLevels:status was renamed to tcbInfo:tcbLevels:tcbStatus.
5. New fields in tcbInfo:tcbLevels named tcbDate and advisoryIDs.

### Get QE Identity Info
1. The 'qeIdentity' block was renamed to 'enclaveIdentity'.
2. A new field, enclaveIdentity:id was added to differentiate QE Id info from Quoting Enclave (QE) and Quoting Validation Enclave (QVE).
3. enclaveIdentity:version changed from 1 to 2.
4. New field enclaveIdentity:tcbEvaluationDataNumber.
5. qeIdentity:isvsvn moved to enclaveIdentity:tcbLevels:tcb:isvsvn.
6. New fields in enclaveIdentity:tcbLevels named tcbData, tcbStatus and advisoryIDs.

### New field definitions

#### tcbType:
	type: integer
	example: 0
	description: >- Type of TCB level composition that determines TCB level comparison logic

##### tcbEvaluationDataNumber:
	type: integer
	example: 2
	description: >- A monotonically increasing sequence number changed when Intel updates the content of the TCB evaluation data set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber update is synchronized across TCB Info for all flavors of SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE Identity. This sequence number allows users to easily determine when a particular TCB Info/QE Idenity/QVE Identiy superseedes another TCB Info/QE Identity/QVE Identity (value: current TCB Recovery event number stored in the database).

##### tcbDate:
	type: string
	format: date-time
	description: >- Representation of date and time when the TCB level was certified not to be vulnerable to any issues described in SAs that were published on or prior to this date. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).

##### tcbStatus:
	type: string
	description: TCB level status

##### advisoryIDs:
	type: array
	description: >- Array of Advisory IDs describing vulnerabilities that this TCB level is vulnerable to. Note: The value can be different for different FMSPCs. This field is optional. It will be present only if the list of Advisory IDs is not empty.
	items:
        type: string

For more information on the new fields please see [API Version 2](https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v2).


## Changes

### Update current structs with new additional fields and create new type definitions.

```C
typedef enum _oe_tcb_level_status
{
    // Existing fields
    OE_TCB_LEVEL_STATUS_UNKNOWN,
    OE_TCB_LEVEL_STATUS_REVOKED,
    OE_TCB_LEVEL_STATUS_OUT_OF_DATE,
    OE_TCB_LEVEL_STATUS_CONFIGURATION_NEEDED,
    OE_TCB_LEVEL_STATUS_UP_TO_DATE,

    // New field for new value "OutOfDateConfigurationNeeded"
    OE_TCB_LEVEL_STATUS_OUTOFDATE_CONFIGURATION_NEEDED,

    __OE_TCB_LEVEL_MAX = OE_ENUM_MAX,

} oe_tcb_level_status_t;

// Existing TCB Level struct for TCB Info.  Will rename this
// struct to oe_tcb_tcb_level given that
// QE identity info also has its TCB level data field.
typedef struct _oe_tcb_level
{
    // Existing fields
    uint8_t sgx_tcb_comp_svn[16];
    uint16_t pce_svn;
    oe_tcb_level_status_t tcb_status;

    // New fields
    oe_datetime_t tcb_date;
    uint8_t* advisory_ids_json;     // ["INTEL-SA-00079", "INTEL-SA-00076"]

} oe_tcb_level_t;

typedef struct _oe_parsed_tcb_info
{
    // Existing fields
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint8_t fmspc[6];
    uint8_t pceid[2];
    uint8_t signature[64];
    const uint8_t* tcb_info_start;
    size_t tcb_info_size;

    // New fields
    uint32_t tcb_type;
    uint32_t tcb_evaluation_data_number;

} oe_parsed_tcb_info_t;

/*!
 * New enum for QE id field
 */
typedef enum _oe_qe_identity_id
{
    OE_IDENTITY_ID_QE,
    QE_IDENTITY_ID_QVE
} oe_qe_identity_id;

/*!
 * New TCB level for QE identity info.
 */
typedef struct _oe_qe_tcb_level
{
    uint32_t isvsvn;
    oe_tcb_level_status_t tcb_status;
    oe_datetime_t tcb_date;
    uint8_t* advisory_ids_json;     // ["INTEL-SA-00079", "INTEL-SA-00076"]

} oe_qe_tcb_level_t;

typedef struct _oe_parsed_qe_identity_info
{
    // Existing fields
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;
    uint32_t miscselect;         // The MISCSELECT that must be set
    uint32_t miscselect_mask;    // Mask of MISCSELECT to enforce
    sgx_attributes_t attributes; // flags and xfrm (XSAVE-Feature Request Mask)
    uint64_t attributes_flags_mask;   // mask for attributes.flags
    uint64_t attributes_xfrm_mask;    // mask for attributes.xfrm
    uint8_t mrsigner[OE_SHA256_SIZE]; // MRSIGNER of the enclave
    uint16_t isvprodid;               // ISV assigned Product ID
    uint16_t isvsvn;                  // ISV assigned SVN
    uint8_t signature[64];
    const uint8_t* info_start;
    size_t info_size;

    // New fields
    oe_qe_identity_id id;
    uint32_t tcb_evaluation_data_number;


} oe_parsed_qe_identity_info_t;
```

### Summary of Processing Changes

The quote verification logic for parsing the TCB Info and the QE Identity Info will need to be updated as well as the validation logic.

1. Update `oe_parse_tcb_info_json()` and `oe_parse_qe_identity_info_json()` to parse the new v2 fields.
2. Account for new TCB status "OutOfDateConfigurationNeeded" in v2 API.
3. TCB info validation updates:
    - version 1:
        - Bug fix.  Will create and address this in a separate issue:
            - Verify `pceid` field matches the one in the PCK Cert.
            - Verify `fmspc` field matches the one in the PCK Cert.
    - version 2:
        - Validate `tcbType` has a value of 0.
        - Check that `tcbEvaluationDataNumber` is at least or equal to the current cached value.  Update cached
        value if the current value is greater than the cached value.
        - TCB Level processing:
            - Account for new tcbStatus "OutOfDateConfigurationNeeded"
            - No additional processing on `tcbDate` and `advisoryIDs`.
4. QE identity info validation updates:
    - version 1: No updates.
    - version 2:
        - Check that `tcbEvaluationDataNumber` is at least or equal to the current cached value.  Update cached
        value if the current value is greater than the cached value.
        - TCB Level processing:
            - Find the first TCB level which the quote's `isvsvn` value is greater than or equal to the corresponding value in the TCB level.
            - Set the `tcbStatus` value from the corresponding TCB level.
            - No additional processing on `tcbDate` and `advisoryIDs`.

Authors
-------

Name: Sergio Wong

email: sewong@microsoft.com

github username: jazzybluesea
