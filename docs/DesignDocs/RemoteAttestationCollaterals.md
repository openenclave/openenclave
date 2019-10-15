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

There are 3 scenarios.

### 1. Verifier does not specify the endorsements:
In this scenario the verifier does not receive any endorsements from the attester (where the TEE resides).  The verifier also does not pass any endorsements to the verification function, instead the endorsements are fetched during verification by the OE SDK.

##### Attester generates the evidence (inside an enclave/TEE)
```C
// Get OE report
result = oe_get_report(
    OE_REPORT_FLAGS_REMOTE_ATTESTATION,
    NULL, // report_data
    0,
    NULL, // opt_params
    0,
    &report,
    report_size);
```

##### Verifier verifies the evidence (in the untrusted host or inside an enclave/TEE)
```C
...

// Verify report without endorsements
result = oe_verify_remote_report_with_endorsements(
            report,
            report_size,
            NULL, // endorsements
            0,    // endorsements_size
            NULL, // input_validation_time
            parsed_report);
...
```

### 2. Verifier is provided with endorsements:
In this scenario the attester/asserter provides the evidence and endorsements to the verifier.  The verifier is then free to use these to verify the TEE.

##### Attester generates the evidence and endorsements (inside an enclave/TEE)
```C
...
result = oe_get_report(
    OE_REPORT_FLAGS_REMOTE_ATTESTATION,
    NULL, // report_data
    0,
    NULL, // opt_params
    0,
    &report,
    report_size);

result = oe_get_endorsements(
    &endorsements,
    &endorsements_size);
...
```

##### Verifier verifies the evidence and endorsements (in the untrusted host or inside an enclave/TEE)
```C
...

// Verify report with endorsements
result = oe_verify_remote_report_with_endorsements(
            report,
            report_size,
            endorsements,
            endorsements_size,
            NULL, // input_validation_time
            NULL, // parsed_report);
...
```

### 3. Verifier specifies endorsements:
In this scenario the attester only provides the evidence to the verifier.  The verifier then fetches the endorsements from a second source different than the OE SDK, and uses the evidence and endorsements to verify the TEE.

##### Attester generates the evidence (inside an enclave/TEE)
```C
...
result = oe_get_report(
    OE_REPORT_FLAGS_REMOTE_ATTESTATION,
    NULL, // report_data
    0,
    NULL, // opt_params
    0,
    &report,
    report_size);
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

// Verify report with endorsements
result = oe_verify_remote_report_with_endorsements(
            report,
            report_size,
            endorsements,
            endorsements_size,
            NULL, // input_validation_time
            NULL, // parsed_report);
...
```

Specification
-------------

### Endorsement structure
Generic serializable structure that stores the endorsements in raw binary format.

`report.h`
```C
/*! \struct oe_endorsements_t
 *
 * \brief OE endorsements
 *
 * Raw generic serializable structure that contains the endorsements.
 *
 */
typedef struct _oe_endorsements_t
{
    uint32_t version;
    uint32_t enclave_type;        ///< The type of enclave
    uint64_t buffer_size;         ///< Size of the buffer
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
    ///<  |  num_elements         |
    ///<  |-----------------------|
    ///<  |  buffer_size          |
    ///<  |-----------------------|
    ///<  |                       |
    ///<  | array of uint32_t     |
    ///<  | of length num_elements|
    ///<  |-----------------------|
    ///<  |  Data                 |
    ///<  |_______________________|
    ///<
    uint8_t buffer[];              ///< Buffer of offsets + data

} oe_endorsements_t;
```

### New Endorsement functions

`endorsements.c`
```C
/*! \struct tee_endorsements
 *
 * \brief SGX endorsements structure
 *
 * The generic oe_endorsements_t structure is parsed and converted into this
 * internal structure.  The order of the generic data elements should
 * coincide with the order of the fields in this structure.
 */
typedef struct _tee_endorsements_t
{
    uint8_t* tcb_info;                      ///< TCB info
    size_t tcb_info_size;                   ///< TCB Info size
    uint8_t* tcb_issuer_chain;              ///< PEM format
    size_t tcb_issuer_chain_size;           ///< Size of the tcb_issuer_chain
    uint8_t* crl[3];                        ///< CRLs
    size_t crl_size[3];                     ///< CRLs sizes
    uint8_t* crl_issuer_chain[3];           ///< PEM format
    size_t crl_issuer_chain_size[3];        ///< Size of each crl_issuer_chain

    uint8_t* qe_id_info;                    ///< QE Identity info
    size_t qe_id_info_size;                 ///< QE Identity size
    uint8_t* qe_id_issuer_chain;            ///< PEM format
    size_t qe_id_issuer_chain_size;         ///< Size of qe_id_issuer_chain

    uint8_t* creation_datetime;             ///< Time the endorsements were generated
    size_t create_datetime_size;            ///< The size of creation_datetime.  Should be 24.

} tee_endorsements_t;

/**
 * Returns the endorsements needed for verification of a remote OE report.
 *
 * This function is only available inside an enclave.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] endorsements_buffer The buffer containing the endorsements to parse.
 * @param[in] endorsements_buffer_size The size of the **endorsements_buffer**.
 *
 * @retval OE_OK The endorsements were successfully retrieved.
 */
oe_result_t oe_get_endorsements(
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * Free up any resources allocated by oe_get_endorsements()
 *
 * @param[in] endorsements_buffer The buffer containing the endorsements.
 */
void oe_free_endorsements(uint8_t* endorsements_buffer);

/**
 * Verify the integrity of the report and its signature,
 * with optional endorsements that are associated with the report. If
 * the endorsements are not specified, this function will fetch
 * the endorsements.  This only applies to remote reports.  For
 * local reports please use oe_verify_report().
 *
 * This function is similar to oe_verify_report() but it supports
 * endorsements.
 *
 * This function is available in the enclave as well as in the host.
 *
 * @param[in] report The buffer containing the report to verify.
 * @param[in] report_size The size of the **report** buffer.
 * @param[in] endorsements Optional The endorsement data that is associated with
 * the report (for remote reports only).
 * @param[in] endorsements_size The size of the **endorsements** buffer.
 * @param[in] input_validation_time Optional datetime to use when validating
 * endorsements. If not specified, it will use the creation_datetime of the
 * endorsements (if any endorsements are provided).
 * @param[out] parsed_report Optional **oe_report_t** structure to populate with
 * the report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report_with_endorsements(
    const uint8_t* report,
    size_t report_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* input_validation_time,
    oe_report_t* parsed_report);
```

### Update existing functions

In the host_verify library, this is the standalone library used for verifying remote reports outside
the TEE/enclave. Update oe_verfiy_remote_report() to take endorsements as an input parameter.

`host/sgx/hostverify_report.c`
```C
/**
 * Verify the integrity of the report and its signature,
 * with optional endorsements that are associated with the report. If
 * the endorsements are not specified, this function will fetch
 * the endorsements.
 *
 * @param[in] report The buffer containing the report to verify.
 * @param[in] report_size The size of the **report** buffer.
 * @param[in] endorsements Optional The endorsement data that is associated with
 * the report (for remote reports only).
 * @param[in] endorsements_size The size of the **endorsements** buffer.
 * @param[in] input_validation_time Optional datetime to use when validating
 * endorsements. If not specified, it will use the creation_datetime of the
 * endorsements (if any endorsements are provided).
 * @param[out] parsed_report Optional **oe_report_t** structure to populate with
 * the report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_remote_report(
    const uint8_t* report,
    size_t report_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_report_t* parsed_report);
```

Alternates
----------

### Endorsement structure:
- Multiple serializable structures were considered.  At the end the final design
made sense given that it is generic and support serialization.  We considered
supporting multiple flavors of the structure, a binary format and another for supporting
user defined endorsements.  But we ended up deciding to have the user build the binary
structure instead, to avoid complexity.

### APIs:
- To reduce complexity, `oe_get_endorsements()` is only available in the enclave.
- To reduce complexity and break existing API users, `oe_verify_remote_report_with_endorsements()`
only supports remote reports.  For local reports use `oe_verify_report()`

Authors
-------

Name: Sergio Wong

email: sewong@microsoft.com

github username: jazzybluesea