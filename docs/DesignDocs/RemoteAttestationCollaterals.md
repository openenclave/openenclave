Remote Attestation Endorsements
=====

Attestation is the process of proving the authenticity of a
Trusted Execution Environment (TEE) platform (HW + software).

In the current API, OE SDK has functions to get the evidence and to verify
the evidence.  This document describes additional changes to the API to
support the concept of endorsements. Endorsements are additional information
from a second source that the verifier can use for attestation verification.

Terminology
----------
From Remote Attestation Procedures Architecture (RATS)
(https://www.ietf.org/id/draft-birkholz-rats-architecture-02.txt).  This
a draft that is Work in Progress and subject to change.

- Evidence is provable Claims about a specific Computing Environment
      made by an Attester.

- Known-Good-Values are reference Claims used to appraise Evidence.

- Endorsements are reference Claims about the environment protecting
      the Attesters capabilities to create believable Evidence (e.g. the
      type of protection for an attestation key).  It answers the
      question "why Evidence is believable".

- Attestation Results are the output from the appraisal of Evidence,
      Known-Good-Values and Endorsements.

       +----------------+                     +-----------------+
       |                |  Known-Good-Values  |                 |
       |   Asserter(s)  |-------------------->|    Verifier     |
       |                |  Endorsements   /-->|                 |
       +----------------+                 |   +-----------------+
                                          |            |
                                          |            |
                                          |            |
                                          |            |Attestation
                                          |            |Results
                                          |            |
                                          |            |
                                          |            v
       +----------------+                 |   +-----------------+
       |                |    Evidence     |   |                 |
       |    Attester    |-----------------/   |  Relying Party  |
       |                |                     |                 |
       +----------------+                     +-----------------+

                           Figure 1: RATS Roles

### Roles

RATS roles are implemented by principals that possess cryptographic
keys used to protect and authenticate Claims or Results.

#### Attester:
An Attestation Function that creates Evidence by
collecting, formatting and protecting (e.g., signing) Claims. It
presents Evidence to a Verifier using a conveyance mechanism or
protocol.

#### Verifier:
An Attestation Function that accepts Evidence from an Attester using
a conveyance mechanism or protocol. It also accepts Known-Good-Values
and Endorsements from an Asserter using a conveyance mechanism or protocol.
It verifies the protection mechanisms, parses and appraises Evidence
according to good-known valid (or known-invalid) Claims and Endorsements.
It produces Attestation Results that are formatted and protected (e.g.,
signed). It presents Attestation Results to a Relying Party using
a conveyance mechanism or protocol.

Claims are statements about a particular subject. They consist of
name-value pairs containing the claim name, which is a string, and
claim value, which is arbitrary data. Example of claims could be
[name="version", value=1] or [name="enclave_id", value=1111].

#### Asserter:
An Attestation Function that generates reference Claims
about both the Attesting Computing Environment and the Attested
Computing Environment. The manufacturing and development
processes are presumed to be trustworthy processes.  In other
words the Asserter is presumed, by a Verifier, to produce valid
Claims. The function collects, formats and protects (e.g. signs)
valid Claims known as Endorsements and Known-Good-Values. It
presents provable Claims to a Verifier using a conveyance
mechanism or protocol.

#### Relying Party:
An Attestation Function that accepts Attestation
Results from a Verifier using a conveyance mechanism or protocol.
It assesses Attestation Results protections, parses and assesses
Attestation Results according to an assessment context (Note:
definition of the assessment context is out-of-scope).


Motivation
----------

Currently, the existing endorsements used for Intel SGX quote verification are not exposed to the user.
This makes it difficult for the verifier to specify his/her own set of policies.
Adding these new APIs allows the verifier to specify a validation policy of his/her choosing.
Possible policies:
1. The verifier has the option to specify its set of endorsements during verification.
2. The verifier has the option to provide a datetime to use during verification.
This datetime specifies the date and time at which the verifier wants to do the verification.
If no datetime is provided, the datetime when the endorsements were created is used during verification.
The verifier can provide a datetime in the past, enabling auditing of the evidence and endorsements.


User Experience
---------------

There are 2 scenarios. Note that to get the endorsements,
currently requires a Data Center Attestation Primitives (DCAP)
client that runs outside the enclave.

### 1. Verifier is provided with endorsements:
In this scenario the attester/asserter provides the evidence and endorsements to the verifier.
The verifier is then free to use these to verify the TEE.

##### Attester generates the evidence and endorsements (inside an enclave/TEE)
```C
...
result = oe_get_evidence(
    OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION,
    NULL, // custom_claims
    0,
    NULL, // opt_params
    0,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);
...
```

##### Verifier verifies the evidence and endorsements (in an untrusted host or inside an enclave/TEE)
```C
...

// Verify report with endorsements
result = oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,  // opt_params
            0,
            &claims,
            &claims_size);
...
```

### 2. Verifier specifies endorsements:
In this scenario the attester only provides the evidence to the verifier.  The verifier then fetches the endorsements from a second source different than the OE SDK, and uses the evidence and endorsements to verify the TEE.

##### Attester generates the evidence (inside an enclave/TEE)
```C
...
result = oe_get_evidence(
    OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION,
    NULL, // custom_claims
    0,
    NULL, // opt_params
    0,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);
...
```

##### Verifier verifies the evidence with custom endorsements (in the untrusted host or inside an enclave/TEE)
```C
...
//
// Verifier gets endorsements not using OE SDK
//

//
// Verifier builds **endorsements** structure
//
endorsements_external = ...
endorsements_external_size = ...

// Verify evidence with external endorsements
result = oe_verify_evidence(
            report,
            report_size,
            endorsements_external,
            endorsements_external_size,
            NULL,  // opt_params
            0,
            &claims,
            &claims_size);
...
```

Specification
-------------

### Public type definitions
Generic serializable public structure that stores the endorsements in raw binary format.

`attestation.h`
```C
/**
 * Flags passed to oe_get_evidence() function.
 */
#define OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION     0x00000000
#define OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION    0x00000001

/*! Limit the size of the endorsements */
#define OE_ATTESTATION_ENDORSEMENT_MAX_SIZE     (20 * 1024)

/*! Endorsement structure version */
#define OE_ATTESTATION_ENDORSEMENT_VERSION      (1)

/*! \struct oe_endorsements_t
 *
 * \brief OE endorsements
 *
 * Raw generic serializable structure that contains the endorsements. All
 * data should be in little endian format.
 *
 */
typedef struct _oe_endorsements_t
{
    uint32_t version;       ///< Version of this structure
    uint32_t enclave_type;  ///< The type of enclave (oe_enclave_type_t)
    uint32_t buffer_size;   ///< Size of the buffer
    uint32_t num_elements;  ///< Number of elements stored in the data buffer

    /*! Data buffer is made of an offset array of type uint32_t, followed by
     * the actual data.
     * This array has the size of **num_elements** and stores the offset
     * into the data section.
     * _________________________
     * |  version              |
     * |-----------------------|
     * |  enclave_type         |
     * |-----------------------|
     * |  buffer_size          |
     * |-----------------------|
     * |  num_elements         |
     * |-----------------------|
     * |  offsets              |
     * |  (array of uint32_t   |
     * |  with length of       |
     * |  num_elements)        |
     * |-----------------------|
     * |  buffer (data)        |
     * |_______________________|
     */
    uint8_t buffer[];              ///< Buffer of offsets + data

} oe_endorsements_t;
```

### Private SGX endorsement definitions

`common/sgx/evidence.h`

```C
/*! Version of the supported SGX endorsement structures */
#define OE_SGX_ENDORSEMENTS_VERSION     (1)

/*! Number of CRLs in the SGX endorsements */
#define OE_SGX_ENDORSEMENTS_CRL_COUNT   (2)

/*! \enum oe_sgx_endorsements_fields
 *
 * Specifies the order of the SGX endorsements fields stored in
 * the oe_endorsements_t structure
 */
typedef enum _oe_sgx_endorsements_fields
{
    OE_SGX_ENDORSEMENT_FIELD_VERSION,
    OE_SGX_ENDORSEMENT_FIELD_TCB_INFO,
    OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN,
    OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT,
    OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA,
    OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT,
    OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO,
    OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN,
    OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME,
    OE_SGX_ENDORSEMENT_COUNT
} oe_sgx_endorsements_fields;

/*! \struct oe_sgx_endorsements
 *
 * \brief SGX endorsements structure
 *
 * The generic oe_endorsements_t structure is parsed and converted into this
 * internal structure.  The order of the generic data elements should
 * coincide with the order of the fields in this structure.
 *
 * Data format: All data comes from the Data Center Attestation Primitives(DCAP)
 * Client.
 *
 * For Azure DCAP Client
 * (https://github.com/microsoft/Azure-DCAP-Client/blob/master/src/dcap_provider.h)
 * see **sgx_ql_revocation_info_t** and **sgx_qe_identity_info_t**.
 *
 * For Intel DCAP Client
 * (https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md)
 * see **sgx_ql_qv_collateral_t**.
 *
 */
typedef struct _oe_sgx_endorsements_t
{
    /*!
     *  OE_SGX_ENDORSEMENT_FIELD_VERSION
     *     Version of this SGX endorsement structure
     *  OE_SGX_ENDORSEMENT_FIELD_TCB_INFO
     *     TCB info, null-terminated JSON string
     *     TCB Info size
     *  OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN
     *     PEM format, null-terminated string
     *     Size of the tcb_issuer_chain
     *
     *  OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT to
     *     OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA
     *  CRLs in DER format, null-terminated
     *      crl[0] = CRL for the SGX PCK Certificate
     *      crl[1] = CRL for the SGX PCK Processor CA
     *
     *  OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT
     *  The SGX PCK CRL issuer chain in PEM format, null-terminated string
     *
     *  OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO
     *     QE Identity info, null-terminated JSON string
     *     QE Identity size
     *  OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN
     *     PEM format, null-terminated string
     *     Size of qe_id_issuer_chain
     *
     *  OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME
     *     Time the endorsements were generated, null-terminated string
     *     The size of creation_datetime.
     */
    oe_sgx_endorsement_item items[OE_SGX_ENDORSEMENT_COUNT];
} oe_sgx_endorsements_t;
```

### New Public Attestation functions

These functions supersede the existing functions:
1. `oe_get_evidence()` supersedes `oe_get_report()`
2. `oe_verify_evidence()` supersedes `oe_verify_report()`

Users should start using these new functions.  `oe_get_report()` and `oe_verify_report()`
are deprecated and will be removed in future releases.

These functions will sit on top of the plug-in attestation framework.  For more information please
see the [attestation plug-in design doc](CustomAttestation.md).  In short, the actual implementation
of these functions will depend on which plug-in is registered.  By default there will
be a built-in SGX plug-in.

`common/sgx/attestation.c`
```C
/**
 * Get evidence signed by the enclave platform along with the corresponding
 * endorsements for use in attestation.
 *
 * This function returns the evidence and endorsements used in **local** or
 * **remote** attestation.
 *
 * For remote attesattion:
 *  - This function can only be called from a TEE/enclave.
 *
 * For local attestation:
 *  - This function can be called from the TEE/enclave or the untrusted host.
 *
 * @param[in] flags Specifying default value (0) generates evidence for local
 * attestation. Specifying OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION generates
 * evidence for remote attestation.
 * @param[in] custom_claims A buffer to the optional custom claims.
 * @param[in] custom_claims_size The size in bytes of custom_claims.
 * @param[in] opt_params Optional additional parameters needed for the current
 * enclave type.
 *     For SGX:
 *        This can be sgx_target_info_t for local attestation.
 * @param[in] opt_params_size The size of the **opt_params** buffer.
 * @param[out] evidence_buffer This points to the resulting evidence upon success.
 * @param[out] evidence_buffer_size This is set to the size of the evidence buffer
 * on success.
 * @param[out] endorsements_buffer The buffer containing the endorsements to parse.
 * @param[out] endorsements_buffer_size The size of the **endorsements_buffer**.
 *
 * @retval OE_OK The evidence and endorsements were successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_evidence(
    uint32_t flags,
    const uint8_t* custom_claims,
    size_t custom_claims_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * Free up any resources allocated by oe_get_evidence()
 *
 * @param[in] evidence_buffer THe buffer containing the evidence.
 * @param[in] endorsements_buffer The buffer containing the endorsements.
 */
void oe_free_evidence(
    uint8_t* endorsements_buffer,
    uint8_t* evidence_buffer);

/**
 * Verify the integrity of the evidence and its signature,
 * with endorsements that are associated with the evidence.
 * This function works for both local and remote attestation.
 *
 * This function is available in the enclave as well as in the host.
 *
 * @param[in] evidence_buffer The buffer containing the evidence to verify.
 * @param[in] evidence_buffer_size The size of the **evidence** buffer.
 * @param[in] endorsements Optional The endorsement data that is associated with
 * the evidence.
 * @param[in] endorsements_size The size of the **endorsements** buffer.
 * @param[in] input_validation_time Optional datetime to use when verifying
 * evidence. If not specified, it will use the creation_datetime of the
 * endorsements (if any endorsements are provided).
 * @param[out] claims The list of claims.
 * @param[out] claims_size The size of claims.
 *
 * @retval OE_OK The verification was successful.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* input_validation_time,
    uint8_t** claims,
    size_t* claims_size);
```

### Claims
As part of the claims form `oe_verify_evidence()`, there will be a validity
datetime range, `validity_from` and `validity_until` claims that applies to the evidence and endorsements.

Current set of claims definitions:

| Claim Name       | Claim Value Type   | Description                                                          |
|:-----------------|:-------------------|:---------------------------------------------------------------------|
| id_version       | uint32_t           | Claims version. Must be 0                                            |
| security_version | uint32_t           | Security version of the enclave. (ISVN for SGX).                     |
| attributes       | uint64_t           | Attributes flags for the evidence: <br/> `OE_REPORT_ATTRIBUTES_DEBUG`: The evidence is for a debug enclave.<br/> `OE_REPORT_ATTRIBUTES_REMOTE`: The evidence can be used for remote attestation.   |
| unique_id        | uint8_t[32]        | The unique ID for the enclave (MRENCLAVE for SGX).                   |
| signer_id        | uint8_t[32]        | The signer ID for the enclave (MRSIGNER for SGX).                    |
| product_id       | uint8_t[32]        | The product ID for the enclave (ISVPRODID for SGX).                  |
| validity_from    | oe_datetime_t      | Overall datetime from which the evidence and endorsements are valid. |
| validity_until   | oe_datetime_t      | Overall datetime at which the evidence and endorsements expire.      |


### OE Host Verify Library

The OE Host Verify library is a standalone library used for verifying remote reports outside
the TEE/enclave. The function `oe_verify_remote_report()` will be updated to support
endorsements.

Authors
-------

Name: Sergio Wong

email: sewong@microsoft.com

github username: jazzybluesea