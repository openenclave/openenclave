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
From Remote Attestation Procedures Architecture
(https://www.ietf.org/id/draft-birkholz-rats-architecture-02.txt).

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
collecting, formatting and protecting (e.g., signing) Claims.  It
presents Evidence to a Verifier using a conveyance mechanism or
protocol.

#### Verifier:
An Attestation Function that accepts Evidence from an Attester using
a conveyance mechanism or protocol.  It also accepts Known-Good-Values
and Endorsments from an Asserter using a conveyance mechanism or protocol.
It verifies the protection mechanisms, parses and appraises Evidence
according to good-known valid (or known-invalid) Claims and Endorsments.
It produces Attestation Results that are formatted and protected (e.g.,
signed).  It presents Attestation Results to a Relying Party using
a conveyance mechanism or protocol.

#### Asserter:
An Attestation Function that generates reference Claims
about both the Attesting Computing Environment and the Attested
Computing Environment.  The manufacturing and development
processes are presumed to be trustworthy processes.  In other
words the Asserter is presumed, by a Verifier, to produce valid
Claims.  The function collects, formats and protects (e.g. signs)
valid Claims known as Endorsements and Known-Good-Values.  It
presents provable Claims to a Verifier using a conveyance
mechanism or protocol.

#### Relying Party:
An Attestation Function that accepts Attestation
Results from a Verifier using a conveyance mechanism or protocol.
It assesses Attestation Results protections, parses and assesses
Attestation Results according to an assessent context (Note:
definition of the assessment context is out-of-scope).


Motivation
----------

Currently, the existing endorsements used for Intel SGX quote verification are not exposed to the user.  This makes it difficult for the verifier to specify his/her own set of policies.  Adding these new APIs allows the verifier to specify a validation policy of his/her choosing.  Possible policies:
1. The verifier has the option to specify its set of endorsements during verification.
2. The verifier has the option to provide a datetime to use during verification.  This datetime specifies the date and time at which the verifier wants to do the verification.  If no datetime is provided, the datetime when the endorsements were created is used during verification.  The verifier can provide a datetime in the past, enabling auditing of the evidence and endorsements.


User Experience
---------------

There are 2 scenarios.

### 1. Verifier is provided with endorsements:
In this scenario the attester/asserter provides the evidence and endorsements to the verifier.  The verifier is then free to use these to verify the TEE.

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

##### Verifier verifies the evidence and endorsements (in the untrusted host or inside an enclave/TEE)
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

### <B>Public</B> type definitions
Generic serializable public structure that stores the endorsements in raw binary format.

`attestation.h`
```C
/**
 * Flags passed to oe_get_evidence() function.
 */
#define OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION  0x00000000
#define OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION 0x00000001

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
    uint32_t version;
    uint32_t enclave_type;        ///< The type of enclave
    uint64_t buffer_size;         ///< Size of the buffer  (oe_enclave_type_t)
    uint32_t num_elements;

    ///< Data buffer is made of an offset array of type uint32_t, followed by
    ///< the actual data.
    ///< This array has the size of **num_elements** and stores the offset
    ///< into the data section.
    ///<  _________________________
    ///<  |  version              |
    ///<  |-----------------------|
    ///<  |  enclave_type         |
    ///<  |-----------------------|
    ///<  |  buffer_size          |
    ///<  |-----------------------|
    ///<  |  num_elements         |
    ///<  |-----------------------|
    ///<  |  offsets              |
    ///<  |  (array of uint32_t   |
    ///<  |  with length of       |
    ///<  |  num_elements)        |
    ///<  |-----------------------|
    ///<  |  Data                 |
    ///<  |_______________________|
    ///<
    uint8_t buffer[];              ///< Buffer of offsets + data

} oe_endorsements_t;


///< Number of CRLs in the SGX endorsements
#define OE_SGX_ENDORSEMENTS_CRL_COUNT     (2)

/*! \enum oe_sgx_endorsements_fields
 *
 * Specifies the order of the SGX endorsements fields stored in
 * the oe_endorsements_t strcuture
 */
typedef enum _oe_sgx_endorsements_fields
{
    OE_SGX_ENDORSEMENT_FIELD_TCB_INFO = 0,
    OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN = 1,
    OE_SGX_ENDORSEMENT_FIELD_CRL_START_INDEX = 2,
    OE_SGX_ENDORSEMENT_FIELD_CRL_END_INDEX =
        OE_SGX_ENDORSEMENT_FIELD_CRL_START_INDEX + OE_SGX_ENDORSEMENTS_CRL_COUNT - 1,

    OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_START_INDEX =
        OE_SGX_ENDORSEMENT_FIELD_CRL_END_INDEX + 1,

    OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_END_INDEX =
        OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_START_INDEX +
        OE_SGX_ENDORSEMENTS_CRL_COUNT - 1,

    OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO =
        OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_END_INDEX + 1,

    OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN,
    OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME

} oe_sgx_endorsements_fields;
```

### <B>Private</B> SGX endorsement definitions

`common/sgx/evidence.h`
```C
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
 * see **sgx_ql_revocation_info_t** and sgx_qe_identity_info_t.
 *
 * For Intel DCAP Client
 * (https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md)
 * see TBD.
 *
 */
typedef struct _oe_sgx_endorsements_t
{
    uint8_t* tcb_info;                      ///< TCB info, null-terminated JSON string
    uint32_t tcb_info_size;                 ///< TCB Info size
    uint8_t* tcb_issuer_chain;              ///< PEM format, null-terminated string
    uint32_t tcb_issuer_chain_size;         ///< Size of the tcb_issuer_chain

    ///< CRLs in DER format, null-terminated
    ///<     crl[0] = CRL for the SGX PCK Certificate
    ///<     crl[1] = CRL for the SGX PCK Processor CA
    uint8_t* crl[OE_SGX_ENDORSEMENTS_CRL_COUNT];

    ///< CRLs sizes
    uint32_t crl_size[OE_SGX_ENDORSEMENTS_CRL_COUNT];

    ///< PEM format, null-terminated string
    uint8_t* crl_issuer_chain[OE_SGX_ENDORSEMENTS_CRL_COUNT];

    ///< Size of each crl_issuer_chain
    uint32_t crl_issuer_chain_size[OE_SGX_ENDORSEMENTS_CRL_COUNT];

    uint8_t* qe_id_info;                    ///< QE Identity info, null-terminated JSON string
    uint32_t qe_id_info_size;               ///< QE Identity size
    uint8_t* qe_id_issuer_chain;            ///< PEM format, null-terminated string
    uint32_t qe_id_issuer_chain_size;       ///< Size of qe_id_issuer_chain

    uint8_t* creation_datetime;             ///< Time the endorsements were generated,
                                            ///< null-terminated string
    uint32_t create_datetime_size;          ///< The size of creation_datetime.

} oe_sgx_endorsements_t;
```

### New <B>Public</B> Attestation functions

These functions supersede the existing functions:
1. `oe_get_evidence()` supersedes `oe_verify_report()`
2. `oe_verify_evidence()` supersedes `oe_verify_report()`

These functions will use plug-in attestation framework.  For more information please
see the design document `CustomAttestation.md`.  In short, the actual implementation
of these functions will depend on which plug-in is registered.  By default there will
be a built-in SGX plug-in.

For more information on the parameters `custom_claims`, `claims` or `opt_params`
please see design document `CustomAttestation.md`.

`common/sgx/attestation.c`
```C
/**
 * Get evidence signed by the enclave platform along with the corresponding
 * endorsements for use in attestation.
 *
 * This function returns the evidence and endorsements used in **local** or
 * **remote** attestation.
 *
 * This function can only be called from a TEE/enclave.
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

### OE Host Verify Library

The OE Host Verify library is a standalone library used for verifying remote reports outside
the TEE/enclave. The function `oe_verfiy_remote_report()` will be deprecated and should use the
upcoming plug-in mode to do verification.


Alternates
----------

### Endorsement structure:
- Multiple serializable structures were considered.  At the end the final design
made sense given that it is generic and support serialization.  We considered
supporting multiple flavors of the structure, a binary format and another for supporting
user defined endorsements.  But we ended up deciding to have the user build the binary
structure instead, to avoid complexity.

### APIs:
- To reduce complexity, `oe_get_evidence()` is only available in the enclave.

Authors
-------

Name: Sergio Wong

email: sewong@microsoft.com

github username: jazzybluesea