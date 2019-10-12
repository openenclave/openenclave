Remote Attestation Collaterals
=====

Adding attestation APIs to support collaterals for remote attestation.  Collaterals are information from a second source that the user/challenger can provide for attestation verification.

Motivation
----------

Currently, the existing collaterals used for Intel SGX quote verification are not exposed to the user.  This makes it difficult for the user/challenger to specify his/her own set of policies.  Adding these new APIs allows the user to specify a validation policy of his/her choosing.  Possible policies:
1. The user/challenger has the option to specify its set of collaterals during verification.
2. The user/challenger has the option to provide a datetime to use during verification.  This datetime specified the date and time at which the user wants to do the verification.  If no datetime is provided, it uses the datetime when the collaterals were created.  The user can provide a datetime in the past, enabling auditing of the evidence and collaterals.


User Experience
---------------

There are 3 scenarios.

### 1. Challenger does not specify the collaterals:
In this scenario the challenger does not receive any collaterals from the attester(where the TEE resides).  The challenger also does not pass any collaterals to the verification function, instead the collaterals are fetched during verification by the OE SDK.

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

##### Challenger verifies the evidence (in the untrusted host)
```C
...

// Verify report without collaterals
result = oe_verify_remote_report_with_collaterals(
            report,
            report_size,
            NULL, // collaterals
            0,    // collaterals_size
            NULL, // input_validation_time
            parsed_report);
...
```

### 2. Challenger is provided with collaterals:
In this scenario the attester provides the evidence and collaterals to the challenger.  The challenger then uses these to verify the TEE.

##### Attester generates the evidence and collaterals (inside an enclave/TEE)
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

result = oe_get_collaterals(
    &collaterals,
    &collaterals_size);
...
```

##### Challenger verifies the evidence and collaterals (in the untrusted host)
```C
...

// Verify report with collaterals
result = oe_verify_remote_report_with_collaterals(
            report,
            report_size,
            collaterals,
            collaterals_size,
            NULL, // input_validation_time
            NULL, // parsed_report);
...
```

### 3. Challenger specifies collaterals:
In this scenario the attester only provides the evidence to the challenger.  The challenger then fetches the collaterals from a second source different than the OE SDK, and uses the evidence and collaterals to verify the TEE.

##### Attester generates the evidence and collaterals (inside an enclave/TEE)
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

##### Challenger verifies the evidence with custom collaterals (in the untrusted host)
```C
...
//
// Challenger gets collaterals not using OE SDK
//

//
// Challenger builds **collaterals** structure
//

// Verify report with collaterals
result = oe_verify_remote_report_with_collaterals(
            report,
            report_size,
            collaterals,
            collaterals_size,
            NULL, // input_validation_time
            NULL, // parsed_report);
...
```

Specification
-------------

### Collateral structure
Generic serializable structure that stores the collaterals in raw binary format.

`report.h`
```C
/*! \struct oe_collaterals_t
 *
 * \brief OE collaterals
 *
 * Raw generic serializable structure that contains the collaterals.
 *
 */
typedef struct _oe_collaterals_t
{
    uint32_t version;
    uint8_t enclave_type;         ///< The type of enclave
    uint8_t reserved;
    uint16_t reserved2;
    uint32_t num_elements;
    size_t buffer_size;           ///< Size of the buffer

    ///< Data buffer is made of an offset array of type uint32_t, followed by
    ///< the actual data.
    ///< This array has the size of **num_elements** and stores the offset
    ///< into the data section.
    ///<  _________________________
    ///<  |  version              |
    ///<  |-----------------------|
    ///<  |  reserved    | type   |
    ///<  |-----------------------|
    ///<  |  num_elements         |
    ///<  |-----------------------|
    ///<  |  buffer_size          |
    ///<  |-----------------------|
    ///<  |                       |
    ///<  |  array(uint32_t)      |
    ///<  |  size of num_elements |
    ///<  |-----------------------|
    ///<  |  Data                 |
    ///<  |_______________________|
    ///<
    uint8_t buffer[];              ///< Buffer of offsets + data

} oe_collaterals_t;
```

### New Collateral functions

`collaterals.c`
```C
/*! \struct sgx_collaterals
 *
 * \brief SGX collateral structure
 *
 * The generic oe_collaterals_t structure is parsed and converted into this
 * internal structure.  The order of the generic data elements should
 * coincide with the order of the fields in this structure.
 */
typedef struct _sgx_collaterals_t
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

    uint8_t* creation_datetime;             ///< Time the collaterals were generated
    size_t create_datetime_size;            ///< The size of creation_datetime.  Should be 24.

} sgx_collaterals_t;

/**
 * Returns the collaterals needed for verification of a remote OE report.
 *
 * This function is only available inside an enclave.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] collaterals_buffer The buffer containing the collaterals to parse.
 * @param[in] collaterals_buffer_size The size of the **collaterals_buffer**.
 *
 * @retval OE_OK The collaterals were successfully retrieved.
 */
oe_result_t oe_get_collaterals(
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size);

/**
 * Free up any resources allocated by oe_get_collateras()
 *
 * @param[in] collaterals_buffer The buffer containing the collaterals.
 */
void oe_free_collaterals(uint8_t* collaterals_buffer);

/**
 * Verify the integrity of the report and its signature,
 * with optional collaterals that is associated with the report. If
 * the collaterals are not specified, this function will fetch
 * the collaterals.  This only applies to remote reports.  For
 * local reports please use oe_verify_report().
 *
 * This function is similar to oe_verify_report() but it supports
 * collaterals.
 *
 * This function is available in the enclave as well as in the host.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] report The buffer containing the report to verify.
 * @param[in] report_size The size of the **report** buffer.
 * @param[in] collaterals Optional The collateral data that is associated with
 * the report (for remote reports only).
 * @param[in] collaterals_size The size of the **collaterals** buffer.
 * @param[in] input_validation_time Optional datetime to use when validating
 * collaterals. If not specified, it will used the creation_datetime of the
 * collaterals (if any collaterals are provided).
 * @param[out] parsed_report Optional **oe_report_t** structure to populate with
 * the report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_remote_report_with_collaterals(
#ifndef OE_BUILD_ENCLAVE
    oe_enclave_t* enclave,
#endif
    const uint8_t* report,
    size_t report_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* input_validation_time,
    oe_report_t* parsed_report);

```

Alternates
----------

### Collateral structure:
- Multiple serializable structures were considered.  At the end the final design
made sense given that it is generic and support serialization.  We considered
supporting multiple flavors of the structure, a binary format and another for supporting
user defined collaterals.  But we ended up deciding to have the user build the binary
structure instead, to avoid complexity.

### APIs:
- To reduce complexity, `oe_get_collaterals()` is only available in the enclave.
- To reduce complexity, `oe_verify_remote_report_with_collaterals()` only supports
remote reports.  For local reports use `oe_verify_report()`

Authors
-------

Name: Sergio Wong

email: sewong@microsoft.com

github username: jazzybluesea