OpenEnclave Pre-measured Content Interface
=======================================

In this paper, we present the interface design for Pre-measured Content support in OpenEnclave. OpenEnclave Pre-measured Content refers to extra content that can be loaded into the enclave post enclave initialization, whose identity is recorded in enclave attestation evidence produced by the underlining enclave TEE environment.

SGX CONFIGID and CONFIGSVN Overview
-----------------

Intel's 10th-gen Core processor and 3rd-gen Xeon-SP support the Key Separation
and Sharing (KSS) feature, including `CONFIGID` and `CONFIGSVN`, which are new
fields defined in `SECS`. `CONFIGID` and `CONFIGSVN` is intended to allow
enclave creator to indicate what additional content may be accepted by the
enclave post enclave initialization. The exact usage depends on the enclave
implementation. `CONFIGSVN` might be used in case `CONFIGID` does not fully
reflect the identity of the additional content. For example, `CONFIGID` can be
set as the hash of the signing key or cert to verify the additional content, and
`CONFIGSVN` can be set as the version number of the signed content. The
`CONFIGID` and `CONFIGSVN` are part of the enclave identity produced by the CPU,
reflecting the identity of the additional code/data allowed to be loaded into
the enclave, committed at the enclave initialization time.

Enclave Creation Interface
-------------------------------------

The Pre-measured Content concept is not limited to SGX TEE. Other TEEs can
potentially support Pre-measured Content, as well as the design of using
config_id/config_svn to indicate the identity of the extra content to be loaded
into the enclave post enclave initialization.

The enclave application passes config_id/config_svn to the enclave loader
through the `OE_ENCLAVE_SETTING_CONTEXT_PRE_MEASURED_ID` type enclave setting
context:

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
    /** Identity of additional content allowed to be loaded into the enclave
     *  post enclave initialization. Currently only supported by SGX Enclaves
     *  with KSS feature enabled.
     */
    OE_ENCLAVE_SETTING_CONTEXT_PRE_MEASURED_ID = 0x976a8f67,
} oe_enclave_setting_type_t;

typedef struct _oe_enclave_pre_measured_id
{
    /** The identity of additional content allowed to be loaded
     *  into the enclave post enclave initialization. The identity is covered
     *  by TEE generated Enclave Attestation Evidence.
     */
    uint8_t config_id[64];
    uint16_t config_svn;
}
oe_enclave_pre_measured_id_t;
```

For SGX, based on whether `OE_ENCLAVE_SETTING_CONTEXT_PRE_MEASURED_ID` is
provided and whether SGX-KSS feature is supported, the SGX enclave loader sets
SECS.config_id and SECS.config_svn according to the table below.

| PREID | Behavior
|-------|-----------------------------------
|   -   | On system where SGX-KSS feature is not available or disabled: No Action; On system with SGX-KSS enabled: loader sets SECS.config_id and SECS.config_svn as 0
|   x   | On system where SGX-KSS feature is not available or disabled: Invalid;  On system with SGX-KSS enabled: loader copies PREID to SECS.config_id and SECS.config_svn

The enclave developer is responsible for the host side code that produces the
identity of the additional content and pass the proper values for
config_id/config_svn to the enclave runtime. The enclave developer should also
implement an explicit function to load the additional content into the enclave
memory post enclave initialization, and to verify the identity and/or SVN of the
loaded content against config_id/config_svn. The exact relationship between the
extra content and config_id/config_svn is defined by the enclave developer.

On SGX CPUs supporting the KSS feature, config_id and config_svn are available in
the SGX `REPORT`. The OE SDK libs will provide an API to retrieve config_id and
config_svn within the enclave.

Attester and Verifier Plugin support
-------------------------------------------------

The Enclave Attestation Attester and Verifier plugins will include config_id and
config_svn as base claims and may include the additional content as custom
claims. For TEE environment that does not support config_id/config_svn, for
example, a SGX enclave running on a SGX CPU that does not support KSS feature,
config_id and config_svn claims should be 0.

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
initialization, identified by config_id/config_svn, is considered "init-time"
claims, as the identity of the extra content is not controlled and can't be
altered by the enclave code at runtime, including the extra content loaded into
the enclave. Combining the "init-time" claims and the "run-time" claims in the
`custom_claims_buffer` field as a single variable length byte-array is possible,
but would require the caller to be aware of plugin-specific implementation of
the internal structure of the combined `custom_claims_buffer` field. A better
solution is to explicitly support the optional "run-time" custom claim buffer
and "init-time" custom claim buffer. Similar to the handling of the "run-time"
customer claim buffer, the placement of the "init-time" customer claim buffer
within the evidence buffer is plugin-specific, but all plugin implementation
should include the the "init-time" customer claim buffer in the evidence buffer.
Different from the handling of the "run-time" customer claim buffer, the
Attester Plugin does not bind the data with certain base claims produced by the
TEE environment, as it's the enclave developer's responsibility to do so.

As the relationship between the "init-time" custom claim buffer and
config_id/config_svn might be defined by the enclave developer, a single
implementation of Verifier Plugin can not accommodate all possible definitions
of config_id/config_svn. The Verifier Plugin should support a default definition
of config_id/config_svn, where config_id is defined as the SHA256 hash of the
`inittime_custom_claims_buffer` content, and verify the integrity of the
content. As defined below, the `inittime_custom_claims_buffer` contains an
integrity algorithm ID, with ID 0 as the default definition each Verifier Plugin
should support if the Plugin supports `inittime_custom_claims_buffer`. A
Verifier Plugin might support other integrity algorithms. If the caller of the
`oe_result_t oe_get_evidence(...)` function sets an integrity algorithm ID not
supported by the Verifier Plugin, the Verifier Plugin should output the
`inittime_custom_claims_buffer` as it is, as an unverified init-time claim. In
that case, the consumer of the outputted claims is responsible to verify the
integrity of the `inittime_custom_claims_buffer` claim using the base claim of
config_id/config_svn.

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
 * runtime custom claims buffer. When provided, the content of the buffer is
 * included in the evidence_buffer as plaintext. The integrity protection of
 * the content is provided by the underlining TEE and the enclave SW outside
 * the plugin.
 * @param[in] inittime_custom_claims_buffer The optional inittime custom claims
 * buffer.
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
 
Authors
-------

Bo Zhang <zhanb@microsoft.com>.
