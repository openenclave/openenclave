# Open Enclave Init-time Configuration Interface

In this paper, we present the interface design for Init-time Configuration
support in Open Enclave. Open Enclave Init-time Configuration feature supports
configurable enclave functionality beyond the static functionality implemented
by the enclave code and initialized data inside the enclave at the enclave
initialization time.

## SGX CONFIGID and CONFIGSVN Overview

Intel's 10th-gen Core processor and 3rd-gen Xeon-SP processor support the SGX
Key Separation and Sharing (KSS) feature, including `CONFIGID` and `CONFIGSVN`,
which are new fields defined in `SECS`, set by the host side SW at Enclave
initialization time. `CONFIGID` and `CONFIGSVN` enable configurable enclave
functionality, in contrast to the static functionality decided by the enclave
code and initialized data, which are reflected in SGX `MRENCLAVE` and can not
change without re-signing the enclave. For example, an enclave app might
configure the enclave with a public key of an external service the enclave will
trust, instead of relying on a hardcoded value. Another form of configurable
enclave functionality is loading additional code/data into the enclave post
enclave initialization. Enclave functionality change based on the configuration
data might have security implication, therefore, the configuration data must be
captured in the enclave attestation. `CONFIGID` and `CONFIGSVN` are part of the
enclave identity produced by the CPU, reflecting the configuration committed at
the enclave initialization time.

The exact usage of `CONFIGID` and `CONFIGSVN` depends on the enclave
implementation. For the use case of loading additional code/data into the
enclave, `CONFIGID` might be used to reflect the hash of additional code/data
to be accepted by the enclave post enclave initialization, or the hash of a
metadata to be loaded into the enclave and used by the enclave code to verify
extra code/data to load. `CONFIGSVN` might be used in case `CONFIGID` does not
fully reflect the identity of the additional content. For example, `CONFIGID`
can be set as the hash of the signing key or cert to verify the metadata, and
`CONFIGSVN` can be set as the version number of the signed metadata.

The scheme of committing the Enclave configuration data into the enclave
identity produced by the CPU at the enclave initialization time is critical for
SGX. For the use case of loading additional code/data, `CONFIGID` and
`CONFIGSVN` reflect the identity of the additional code/data allowed to be
loaded into the enclave. The identity must be immutable at enclave run time.
Otherwise, the loaded code/data might be able to spoof its own identity. For
instance, consider an enclave containing a JavaScript interpreter that executes
user scripts that originate from the untrusted host in shared enclave memory,
and which has access to the `oe_get_evidence` API. It is impossible to know
which script has been executed by such an enclave based on traditional evidence,
even if the hash of the script is supposed to be included in the
`REPORT.report_data`, because a malicious script can set `REPORT.report_data`
and obtain valid evidence via `oe_get_evidence`. Similarly, if an enclave loads
and executes arbitrary assembly code from the host, this assembly code can use
the SGX `EREPORT` instruction to create valid evidence reporting a spoofed
identity of the loaded code. With `CONFIGID` and `CONFIGSVN` set at enclave
initialization time, and accessible to the enclave code, the static code of the
enclave makes sure the user script or assembly code loaded into the enclave
match the identity captured in `CONFIGID` and `CONFIGSVN`, before transferring
the execution control to the loaded code. Even if the loaded code is malicious,
the code has no ability to spoof its own identity.  

## Enclave Creation Interface

The configurable enclave functionality concept is not limited to SGX TEE. Other
TEEs can potentially support this concept, including the aspect of immutable
identity of additional code/code allowed to be loaded into the enclave post
enclave initialization. But at the time of the writing, only SGX with KSS feature supports Init-time Configuration Data.  

An OE SGX application passes the Init-time Configuration Data to the enclave
loader through the `OE_SGX_CONFIG_DATA` enclave setting context:

```C
/**
 * Types of settings passed into **oe_create_enclave**
 */
typedef enum _oe_enclave_setting_type
{
    OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS = 0xdc73a628,
#ifdef OE_WITH_EXPERIMENTAL_EEID
    OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA = 0x976a8f66,
#endif
    /** Enclave configuration data committed at Enclave initialization time,
     *  reflected in TEE-produced enclave identity evidence. Currently only
     *  supported by SGX Enclaves with KSS feature enabled.
     */
    OE_SGX_CONFIG_DATA = 0x78b5b41d
} oe_enclave_setting_type_t;

typedef struct _oe_sgx_config_data
{
    uint8_t configid[8];
    uint16_t configsvn;
}
oe_sgx_config_data_t;
```

For SGX, based on whether `OE_SGX_CONFIG_DATA` is provided and whether SGX-KSS
feature is supported, the SGX enclave loader sets SECS.CONFIGID and
SECS.CONFIGSVN according to the table below.

| CONFIGURATION_DATA | Behavior
|-------|-----------------------------------
|   -   | On system where SGX-KSS feature is not available or disabled: No Action; On system with SGX-KSS enabled: loader sets SECS.CONFIGID and SECS.CONFIGSVN as 0
|   x   | On system where SGX-KSS feature is not available or disabled: Invalid;  On system with SGX-KSS enabled: loader copies _oe_sgx_config_data to SECS.CONFIGID and SECS.CONFIGSVN

The enclave developer is responsible for the host side code that produces the
Enclave Configuration Data and pass the data to the enclave loader. The enclave
developer should also implement an explicit function to load the additional
content into the enclave memory post enclave initialization, and to verify the
loaded content against the Enclave Configuration Data, if the Configuration Data
is used to covey the identity of the extra content. The exact relationship
between the extra content and the Enclave Configuration Data is defined by the
enclave developer.

On SGX CPUs supporting the KSS feature, configid and configsvn are available in
the SGX `REPORT`. The OE SDK libs will provide an API to retrieve configid and
configsvn within the enclave.

In the future, when more TEEs support Init-time Configuration Data, the interface might be expanded to support TEE-agnostic Init-time Configuration Data.

## Attester and Verifier Plugin support

The Enclave Attestation Attester and Verifier plugins will include the Enclave
Init-time Configuration Data as base claims and may include the additional
content as custom claims. For TEE environment that does not support Enclave
Init-time Configuration, for example, a SGX enclave running on a SGX CPU that
does not support KSS feature, the Enclave Init-time Configuration Data claims
should be 0.

Currently, the `oe_result_t oe_get_evidence(...)` function each Attester Plugin
must support specifies the `custom_claims_buffer` as a variable length
byte-array, whose relationship with other base claims are defined by each
Attester/Verifier plugin. Typically, the plugins define the customer claims as
"run-time" claims made by Enclave code, and protect the integrity of the data by
binding the data with certain base claims produced by the TEE environment. For
example, SGX Attester Plugin implementations set the `ReportData` field of the
SGX `REPORT` produced by the CPU as the SHA256 hash of the
`custom_claims_buffer`.  SGX Enclave code can generate a RSA key pair, and
include the RSA public key in the custom claims, to be used by a remote entity
to wrap secrets to be delivered to the enclave, after verification of the
attestation.

The extra content that can be loaded into the enclave post enclave
initialization, identified by the Enclave Init-time Configuration Data, can be
considered "init-time" claims. Combining the "init-time" claims and the
"run-time" claims in the `custom_claims_buffer` field as a single variable
length byte-array is possible, but would either require the caller to be aware
of plugin-specific implementation of the internal structure of the combined
`custom_claims_buffer` field, or the Verifier to be aware of the caller defined internal structure.

### Plugin API change with explicit init-time custom claim buffer support 

One solution is to explicitly support the optional "run-time" custom claim
buffer and "init-time" custom claim buffer. Similar to the handling of the
"run-time" customer claim buffer, the placement of the "init-time" customer
claim buffer within the evidence buffer is plugin-specific, but all plugin
implementations supporting Enclave Init-time Configuration should include the
the "init-time" customer claim buffer in the evidence buffer. Different from the
handling of the "run-time" customer claim buffer, the Attester Plugin does not
bind the data with certain base claims produced by the TEE environment, as it's
the enclave developer's responsibility to do so.

As the relationship between the "init-time" custom claim buffer and the Enclave
Init-time Configuration Data is defined by the enclave developer, a single
implementation of Verifier Plugin can not accommodate all possible definitions
of Enclave Init-time Configuration Data. The Verifier Plugin should support a
default definition of Enclave Init-time Configuration Data, where the first 32
bytes of the the Enclave Init-time Configuration Data is defined as the SHA256
hash of the `inittime_custom_claims_buffer` content, and verify the integrity of
the content. As defined below, the `inittime_custom_claims_buffer` contains an
integrity algorithm ID, with ID 0 as the default definition each Verifier Plugin
should support if the Plugin supports `inittime_custom_claims_buffer`. A
Verifier Plugin might support other integrity algorithms. If the caller of the
`oe_result_t oe_get_evidence(...)` function sets an integrity algorithm ID not
supported by the Verifier Plugin, the Verifier Plugin should output the
`inittime_custom_claims_buffer` as it is, as an unverified init-time claim. In
that case, the consumer of the outputted claims is responsible to verify the
integrity of the `inittime_custom_claims_buffer` claim using the base claim of
configid/configsvn.

```C
/**
 * oe_get_evidence
 *
 * Generates the evidence for the given format id.
 * This function is only available in the enclave.
 *
 * @param[in] format_id The format ID of the evidence to be generated.
 * @param[in] flags A bit-wise parameter. Currently there is one bit
 * defined: OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID. If this bit is set,
 * the evidence and endorsements will be wrapped with a header containing
 * the format ID.
 * @param[in] runtime_custom_claims_buffer The optional runtime custom claims
 * buffer. When provided, the content of the buffer is included in the
 * evidence_buffer, with integrity protection. Depending on the underlining TEE
 * and the plugin implementation, the content might or might not be further
 * encrypted.
 * @param[in] runtime_custom_claims_buffer_size The number of bytes in the
 * runtime custom claims buffer.
 * @param[in] inittime_custom_claims_buffer The optional inittime custom claims
 * buffer. When provided, the content of the buffer is included in the
 * evidence_buffer as plaintext. The integrity protection of the content is
 * provided by the underlining TEE and the enclave SW outside the plugin.
 * @param[in] inittime_custom_claims_buffer_size The number of bytes in the
 * inittime custom claims buffer.
 * @param[in] optional_parameters The optional format-specific input parameters.
 * @param[in] optional_parameters_size The size of optional_parameters in bytes.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the dynamically allocated evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer in bytes.
 * @param[out] endorsements_buffer If not NULL, an output pointer that will be
 * assigned the address of the dynamically allocated endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer in bytes.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND The input evidence format id is not supported.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
    uint32_t flags,
    const void* runtime_custom_claims_buffer,
    size_t runtime_custom_claims_buffer_size,
    const oe_inittime_custom_claim_buffer_t* inittime_custom_claims_buffer,
    size_t inittime_custom_claims_buffer_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

typedef struct _oe_inittime_custom_claim_buffer_t
{
    /* ID of integrity algorithm to be used to verify the buffer content.
     *   0: config_id = SHA256(buffer[]);
     *   others: undefined;
     */
    uint32_t integrity_algorithm_id;
    /* Variable length buffer */
    char buffer[];
} oe_inittime_custom_claim_buffer_t;
```

The following pseudocode demonstrates how the proposed interface can be used.

```C
    /// Untrusted Code of the OE Application
    ///

    // Set up extra content and configid
    rsa3072_public_key_t  pubkey = {...};
    oe_sgx_config_data_t = 
    {
        SHA256(pubkey), // configid
        0
    };
    oe_enclave_setting_t settings[] =
    {
        {
            setting_type = OE_SGX_CONFIG_DATA,
            u.oe_sgx_config_data_t = &oe_sgx_config_data_t
        }
    };
    // Create enclave
    oe_create_enclave(..., settings, ...);

    /// Enclave code of the OE Application
    ///

    // Load the pubkey into enclave memory and verify it against
    // configid
    ...

    // Set up init-time claims for attestation
    uint8 claim_buffer[sizeof(uint32_t)+sizeof(rsa3072_public_key_t)];
    oe_inittime_custom_claim_buffer_t *p_inittime_custom_claims_buffer 
                                          = claim_buffer;

    p_inittime_custom_claims_buffer->integrity_algorithm_id = 0;
    memcpy(p_inittime_custom_claims_buffer->buffer, pubkey,
           sizeof(rsa3072_public_key_t));
  
    size_t inittime_custom_claims_buffer_size =
        sizeof(claim_buffer);

    // Generate evidence #1
    oe_get_evidence(...,
        runtime_custom_claims_buffer_1,
        runtime_custom_claims_buffer_size_1,
        p_inittime_custom_claims_buffer,
        inittime_custom_claims_buffer_size,
        evidence_buffer_1,
        ...);
    // Send evidence to Verifier
    send_evidence_to_REST_URL(..., evidence_buffer_1, evidence_buffer_size_1,...);
    ...

    // Generate evidence #2
    oe_get_evidence(...,
        runtime_custom_claims_buffer_2,
        runtime_custom_claims_buffer_size_2,
        p_inittime_custom_claims_buffer,
        inittime_custom_claims_buffer_size,
        evidence_buffer_2,
        ...);

    // Send evidence to Verifier
    send_evidence_to_REST_URL(..., evidence_buffer_2, evidence_buffer_size_2,...);


    /// Verifier Plugin
    ///
    oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
    {
        ...
        //extract the init_time_claims_buffer and verify it 
        inittime_claims_buffer = _find_init_time_claim_buffer(evidence_buffer,
                                   evidence_buffer_size);
        inittime_claims_buffer_size = _find_init_time_claim_buffer_si(
                                        evidence_buffer, evidence_buffer_size);
        configid = _find_config_id(evidence_buffer, evidence_buffer_size);
        if (inittime_claim_buffer.integrity_algorithm_id ! = 0 )
            return error;
        if (SHA256(inittime_claim_buffer.buffer, inittime_claims_buffer_size)
              != configid)
            return error;
        //output init_time claims
        ...
    }



    /// Verifier
    ///

    // Verify evidence
    oe_verify_evidence(...,
            evidence_buffer,
            ...,
            &claims,
            &claims_length);
    // Check claims against policy, including init_time claims
    // reported by the plugin.
    ...
```

### Alternative Design with no Plugin API change

Alternatively, the responsibility of "init-time" claims packaging and
verification can be removed from the Attester/Verifier plugin and left to the
upper level SW to implement. The upper level SW can append the "init-time" claim
buffer to the evidence buffer returned by `oe_get_evidence` and send to the the
Verifier, which is expected to verify the integrity of the "init-time" claim
buffer received using the Enclave Init-time Configuration Data base claim. In
this approach, the upper level SW within the attesting Enclave app and the
Verifier should establish an agreement on the implementation-specific integrity
algorithm. In this solution, the `oe_get_evidence` API does not require any change other than clarification on the `custom_claims_buffer` definition.

```C
/**
 * oe_get_evidence
 *
 * Generates the evidence for the given format id.
 * This function is only available in the enclave.
 *
 * @param[in] format_id The format ID of the evidence to be generated.
 * @param[in] flags A bit-wise parameter. Currently there is one bit
 * defined: OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID. If this bit is set,
 * the evidence and endorsements will be wrapped with a header containing
 * the format ID.
 * @param[in] custom_claims_buffer The optional runtime custom claims
 * buffer. When provided, the content of the buffer is included in the
 * evidence_buffer, with integrity protection. Depending on the underlining TEE
 * and the plugin implementation, the content might or might not be further
 * encrypted.
 * @param[in] custom_claims_buffer_size The number of bytes in the
 * runtime custom claims buffer.
 * @param[in] optional_parameters The optional format-specific input parameters.
 * @param[in] optional_parameters_size The size of optional_parameters in bytes.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the dynamically allocated evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer in bytes.
 * @param[out] endorsements_buffer If not NULL, an output pointer that will be
 * assigned the address of the dynamically allocated endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer in bytes.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND The input evidence format id is not supported.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
    uint32_t flags,
    const void* custom_claims_buffer,
    size_t custom_claims_buffer_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);
```

The following pseudocode demonstrates how the proposed interface can be used. 
```C

    /// Untrusted Code of the OE Application
    ///

    // Set up extra content and configid
    rsa3072_public_key_t  pubkey = {...};
    oe_sgx_config_data_t = 
    {
        SHA256(pubkey), // configid
        0
    };
    oe_enclave_setting_t settings[] =
    {
        {
            setting_type = OE_SGX_CONFIG_DATA,
            u.oe_sgx_config_data_t = &oe_sgx_config_data_t
        }
    };
    // Create enclave
    oe_create_enclave(..., settings, ...);

    /// Enclave code of the OE Application
    ///

    // Load the pubkey into enclave memory and verify it against
    // configid
    ...

    // Set up init-time claims for attestation
    uint8 claim_buffer[sizeof(uint32_t)+sizeof(rsa3072_public_key_t);
    oe_inittime_custom_claim_buffer_t *p_inittime_custom_claims_buffer
                                                        = claim_buffer;

    p_inittime_custom_claims_buffer->integrity_algorithm_id = 0;
    memcpy(p_inittime_custom_claims_buffer->buffer, pubkey,
           sizeof(rsa3072_public_key_t));
  
    size_t inittime_custom_claims_buffer_size =
        sizeof(claim_buffer);

    // Generate evidence #1
    oe_get_evidence(...,
        runtime_custom_claims_buffer_1,
        runtime_custom_claims_buffer_size_1,
        evidence_buffer_1,
        ...);

    //Assemble the data buffer with evidence and inittime_claim
    ...
    data_buffer->evidence_buffer_size = evidence_buffer_size_1;
    data_buffer->inittime_claims_buffer_size = inittime_custom_claims_buffer_size;
    memcpy(data_buffer->data, evidence_buffer_1, evidence_buffer_size_1);
    memcpy(data_buffer->data + evidence_buffer_size_1;
       p_inittime_custom_claims_buffer, inittime_custom_claims_buffer_size);
    ...

    // Send data_buffer to Verifier
    send_evidence_to_REST_URL(..., data_buffer, data_buffer_size, ....);
    ...

    // Generate evidence #2
    oe_get_evidence(...,
        runtime_custom_claims_buffer_2,
        runtime_custom_claims_buffer_size_2,
        p_inittime_custom_claims_buffer,
        inittime_custom_claims_buffer_size,
        evidence_buffer_2,
        ...);

    //Assemble the data buffer with evidence and inittime_claim
    ...
    data_buffer->evidence_buffer_size = evidence_buffer_size_2;
    data_buffer->inittime_claims_buffer_size = inittime_custom_claims_buffer_size;
    memcpy(data_buffer->data, evidence_buffer_1, evidence_buffer_size_2);
    memcpy(data_buffer->data + evidence_buffer_size_2;
      p_inittime_custom_claims_buffer, inittime_custom_claims_buffer_size);
    ...

    // Send evidence to Verifier
    send_evidence_to_REST_URL(..., data_buffer, data_buffer_size,...);

    /// Verifier Plugin
    ///
    oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
    {
        ...
        //extract the customer_claims_buffer and verify it
        custom_claims_buffer = _find_custom_time_claim_buffer(evidence_buffer,
                               evidence_buffer_size);
        custom_claims_buffer_size = _find_init_time_claim_buffer_size(
                                    evidence_buffer, evidence_buffer_size);
        report_data = _find_report_data(evidence_buffer, evidence_buffer_size);
        if (SHA256(custom_claims_buffer, custom_claims_buffer_size) != report_data)
            return error;
        // has to output the custom claim buffer as a whole, as the buffer
        // internal structure is opaque to the Plugin.
        oe_add_claim(claims, custom_claims_buffer, custom_claims_buffer_size,
                     OE_SGX_CUSTOM_CLAIM_BUFFER)
        ...
    }


    /// Verifier
    ///

    // Verify evidence
    oe_verify_evidence(...,
            data_buffer->data,
            data_buffer->evidence_buffer_size,
            ...,
            &claims,
            &claims_length);
    // Check claims provided by Verifier Plugin against policy,
    ...
    // Verifier has to validate init-time claims buffer
    configid = _find_claim(claims, claims_length, OE_SGX_CONFIGID);
    // check init-time claim  
    p_init_time_custom_claims_buffer = data_buffer->data + evidence_buffer_size;
    if (p_inittime_claim_buffer->integrity_algorithm_id ! = 0 )
            return error;
    if (SHA256(p_inittime_claim_buffer->buffer,
        data_buffer->inittime_claims_buffer_size -
        sizeof(p_inittime_claim_buffer->integrity_algorithm_id)) != configid)
            return error;
    ...
    // Check p_inittime_claim_buffer->buffer against policy.
    ...
```

In the alternative design, the caller of `oe_get_evidence` is not supposed to include the init-time customer claim buffer inside the `custom_claim_buffer` input to the API. If the caller does so indeed, the Verifier logic would have to change. The The following pseudocode shows the difference.

```C

    /// Untrusted Code of the OE Application
    ///

    // Set up extra content and configid
    rsa3072_public_key_t  pubkey = {...};
    oe_sgx_config_data_t = 
    {
        SHA256(pubkey), // configid
        0
    };
    oe_enclave_setting_t settings[] =
    {
        {
            setting_type = OE_SGX_CONFIG_DATA,
            u.oe_sgx_config_data_t = &oe_sgx_config_data_t
        }
    };

    // Create enclave
    oe_create_enclave(..., settings, ...);

    /// Enclave code of the OE Application
    ///

    // Load the pubkey into enclave memory and verify it against
    // configid
    ...

    // Set up init-time claims for attestation
    uint8 claim_buffer[sizeof(uint32_t)+sizeof(rsa3072_public_key_t);
    oe_inittime_custom_claim_buffer_t *p_inittime_custom_claims_buffer
                                                        = claim_buffer;

    p_inittime_custom_claims_buffer->integrity_algorithm_id = 0;
    memcpy(p_inittime_custom_claims_buffer->buffer, pubkey,
           sizeof(rsa3072_public_key_t));
  
    size_t inittime_custom_claims_buffer_size =
        sizeof(claim_buffer);

    // Generate evidence #1
    //Assemble the runtime claim and initime claim into a single custom claim buffer
    ...
    claim_buffer->runtime_claims_buffer_size= runtime_custom_claims_buffer_size_1;
    claim_buffer->inittime_claims_buffer_size = inittime_custom_claims_buffer_size;
    memcpy(claim_buffer->data, runtime_custom_claims_buffer_1,
           runtime_custom_claims_buffer_size_1);
    memcpy(data_buffer->data + runtime_custom_claims_buffer_size_1;
           p_inittime_custom_claims_buffer, inittime_custom_claims_buffer_size);
    ...
    oe_get_evidence(...,
        claim_buffer,
        sizeof(claim_buffer)
            + claim_buffer->runtime_claims_buffer_size
            + claim_buffer->inittime_claims_buffer_size,
        evidence_buffer_1,
        ...);

    // Send evidence to Verifier
    send_evidence_to_REST_URL(..., evidence_buffer_1, evidence_buffer_size_1, ....);
    ...

    // Generate evidence #2
    //Assemble the runtime claim and initime claim into a single custom claim buffer
    ...
    claim_buffer->runtime_claims_buffer_size= runtime_custom_claims_buffer_size_2;
    claim_buffer->inittime_claims_buffer_size = inittime_custom_claims_buffer_size;
    memcpy(claim_buffer->data, runtime_custom_claims_buffer_2,
           runtime_custom_claims_buffer_size_2);
    memcpy(data_buffer->data + runtime_custom_claims_buffer_size_2;
           p_inittime_custom_claims_buffer, inittime_custom_claims_buffer_size);
    ...
    oe_get_evidence(...,
        claim_buffer,
        sizeof(claim_buffer)
            + claim_buffer->runtime_claims_buffer_size
            + claim_buffer->inittime_claims_buffer_size,
        evidence_buffer_2,
        ...);
    ...
    // Send evidence to Verifier
    send_evidence_to_REST_URL(..., evidence_buffer_2, evidence_buffer_size_2,...);

    /// Verifier Plugin
    ///
    oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
    {
        ...
        //extract the customer_claims_buffer and verify it
        custom_claims_buffer = _find_custom_time_claim_buffer(evidence_buffer,
                                evidence_buffer_size);
        custom_claims_buffer_size = _find_init_time_claim_buffer_size(
                                     evidence_buffer, evidence_buffer_size);
        report_data = _find_report_data(evidence_buffer, evidence_buffer_size);
        if (SHA256(custom_claims_buffer, custom_claims_buffer_size) != report_data)
            return error;
        // has to output the custom claim buffer as a whole, as the buffer
        // internal structure is opaque to the Plugin.
        oe_add_claim(claims, custom_claims_buffer, custom_claims_buffer_size,
                     OE_SGX_CUSTOM_CLAIM_BUFFER);
        ...
    }


    /// Verifier
    ///

    // Verify evidence
    oe_verify_evidence(...,
            evidence_buffer,
            evidence_buffer_size,
            ...,
            &claims,
            &claims_length);
    // Check claims provided by Verifier Plugin against policy,
    ...
    // Verifier has to validate init-time claims buffer within the
    // OE_SGX_CUSTOM_CLAIM_BUFFER claim
    configid = _find_claim(claims, claims_length, OE_SGX_CONFIGID);
    data_buffer = _find_claim(claims, claims_length, OE_SGX_CUSTOM_CLAIM_BUFFER);
    // check init-time claim buffer within the data_buffer
    p_init_time_custom_claims_buffer = data_buffer->data +
        data_buffer->runtime_claims_buffer_size;
    if (p_inittime_claim_buffer->integrity_algorithm_id ! = 0 )
            return error;
    if (SHA256(p_inittime_claim_buffer->buffer,
               data_buffer->inittime_claims_buffer_size
                 - sizeof(p_inittime_claim_buffer->integrity_algorithm_id))
        != configid)
            return error;
    ...
    // Check p_inittime_claim_buffer->buffer against policy.
    ...
```

### Recommendation

The alternative design where the caller of the Plugins is responsible for
"init-time" claims packaging and verification is chosen, for its flexibility and
clear designation of the responsibilities between the Plugin developers and
Application developers.

It's suggested that The Application developers
concatenate "init-time" claims buffer and the evidence buffer returned by the Attester Plugin based on their own protocol.

## Authors

Bo Zhang <zhanb@microsoft.com>.
