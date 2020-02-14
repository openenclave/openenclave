___

Custom Attestation Data Formats for Open Enclave
=====

This design document proposes a new attestation framework and set of APIs that
enable developers to use custom formats for their attestation data.  

Motivation
----------

Currently, Open Enclave provides several APIs that developers can use for
attestation. The two key functions are `oe_get_report`, which produces an opaque
blob that is signed by the enclave, and `oe_verify_report`, which can be used to
verify the generated report. The original purpose of those two APIs were to
provide a simple, cross-platform way to produce and verify attestation data.

However, some developers need more flexibility for their attestation
requirements. For example, one might want to extend Open Enclave's
current attestation structures with extra information, such as geolocation
or a timestamp. Another user might want their enclaves to generate attestation
data that is in a format compatible with their existing authentication
infrastructure, such as a JSON Web Token or an X.509 certificate. There are also
users who want to specify their endorsements (information from a second source
used for verification), instead of using the set of endorsements provided by Open
Enclave.

Overall, there has been interest in enhancing Open Enclave's APIs to support
custom attestation formats to enable these scenarios.

Terminology
-----------

This document uses the following terminology defined below. Note that
these definitions are consistent with the terms defined in the
[Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/)
working group.

- Claims
  - Claims are statements about a particular subject. They consist of
    name-value pairs containing the claim name, which is a string, and
    claim value, which is arbitrary data. Example of claims could be
    [name="version", value=1] or [name="enclave_id", value=1111].
- Evidence
  - Evidence is claims about the enclave that are produced and signed by it.
    The SGX report would be an example of evidence.
- Endorsements
  - Endorsements are additional claims used in the evidence verification process,
    but not produced by the enclave. An example of an endorsement would be
    the quoting enclave's identity used in SGX remote attestation, because it
    is retrieved from Intel's servers, rather than the enclave.
- Attester
  - The attester creates the evidence and signs it. Trusted Execution Environments
    (TEEs), such as the SGX enclave, often play the role of the attester.
- Verifier
  - The verifier is responsible for taking in the evidence and endorsements
    and deciding if the enclave is trustworthy.
- Relying party
  - The relying party is the entity interested in communicating with an
    enclave. The enclave must attest to the relying party before the
    relying party can trust it. The relying party can also play the role
    of the verifier, but it does not necessarily have to.

Specification
-------------

To support custom attestation formats, this document proposes adding a plugin
model for attestation. The Open Enclave SDK will define a plugin API for the
attester and another API for the verifier. Each plugin will define a UUID to
distinguish plugins. An attester and verifier plugin sharing the same UUID
indicates that that verifier is able to process the evidence format generated
by the attester.

Futhermore, there will be additional attestation "plugin aware" APIs that are
analogous to `oe_get_report` and `oe_verify_report` called `oe_get_evidence`
and `oe_verify_evidence` respectively. There will also
be functions for registering and unregistering plugins called
`oe_register_[attester|verifier]` and `oe_unregister_[attester|verifier]`. The user
can link in their desired plugin and call the register plugin function.
The attestation data can be retrieved from `oe_get_evidence` with the desired UUID.
The generated data will have the UUID in its header. The user can call `oe_verify_evidence` to verify the data and the Open Enclave runtime can use this
UUID to determine what plugin verification routine to run.

If the plugin is registered on the enclave side, it will only work for the enclave side.
Likewise, if the plugin is registered for the host side, it will only work for the
host side. If the user wants to use the plugin for both sides, then they must register
it once inside the enclave and once inside the host.

### Common Attestation Plugin Struct Definitions

The following structs and enums are used by the attester and verifier plugins
and are defined below for reference:

```C
/**
 * The size of a UUID in bytes.
 */
#define OE_UUID_SIZE 16

/**
 * Struct containing the definition for an UUID.
 */
typedef struct _oe_uuid_t
{
    uint8_t b[OE_UUID_SIZE];
} oe_uuid_t;

/**
 * Claims struct used for claims parameters for the attestation plugins.
 */
typedef struct _oe_claim
{
    char* name;
    uint8_t* value;
    size_t value_size;
} oe_claim_t;

/**
 * Supported policies for validation by the verifier attestation plugin.
 * Only time is supported for now.
 */
typedef enum _oe_policy_type
{
    /**
     * Enforces that time fields in the endorsements will be checked in
     * with the given time rather than the endorsement creation time.
     *
     * The policy will be in the form of `oe_datetime_t`.
     */
    OE_POLICY_ENDORSEMENTS_TIME = 1
} oe_policy_type_t;

/**
 * Generic struct for defining policy for the attestation plugins.
 */
typedef struct _oe_policy
{
    oe_policy_type_t type;
    void* policy;
    size_t policy_size;
} oe_policy_t;
```

### Base Attestation Role Plugin API

Each attestation plugin will have a base structure defined by the following
struct. The struct contains the plugin UUID and functions for registering
and unregistering the plugin. Each specific attestation role (e.g. attester)
will extend the struct and define the necessary functions for that role (e.g.
`get_evidence` for attester).

```C
/**
 * Struct that defines the base structure of each attestation role plugin.
 * Each attestation role will have an UUID to indicate what evidence format
 * is supported and have functions for registering/unregistering the plugin.
 * Each attestation role will also define the require function for their
 * specific role (i.e. `get_evidence` for the attester and `verify_evidence`
 * for the verifier).
 */
typedef struct _oe_attestation_role oe_attestation_role_t;
struct _oe_attestation_role
{
    /**
     * The UUID for the attestation role.
     */
    oe_uuid_t format_id;

    /**
     * The function that gets executed when the attestation role is registered.
     *
     * @param[in] context A pointer to the attestation role struct.
     * @param[in] config_data An optional pointer to the configuration data.
     * @param[in] config_data_size The size in bytes of config_data.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_register)(
        oe_attestation_role_t* context,
        const void* config_data,
        size_t config_data_size);

    /**
     * The function that gets executed when the attestation role is
     * unregistered.
     *
     * @param[in] context A pointer to the attestation role struct.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_unregister)(oe_attestation_role_t* context);
};
```

Here is the rationale for each element in the plugin struct:
- `format_id`
  - Each plugin needs a unique identifier to distinguish itself.
- `on_register` and `on_unregister`
  - A plugin might require some setup or teardown when it is registered or
    unregistered, so these functions are required. Furthermore, a plugin
    might require configuration, which is why there is a `config_data`
    parameter. The configuration data can be plugin specific, so no format is
    specified in this proposal.

### Attester Plugin API (Enclave only)

Each attester plugin must implement the functions below:

```C
/**
 * The attester attestation role. The attester is responsible for generating the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_attester oe_attester_t;
struct _oe_attester
{
    /**
     * The base attestation role containing the common functions for each role.
     */
    oe_attestation_role_t base;

    /**
     * Generates the attestation evidence, which is defined as the data
     * produced by the enclave. The caller may pass in custom claims, which
     * must be attached to the evidence and then cryptographically signed.
     *
     * Note that many callers of `get_evidence` will send the results over
     * the network, so the output must be in a serialized form.
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] flags Specifying default value (0) generates evidence for
     * local attestation. Specifying OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION
     * generates evidence for remote attestation.
     * @param[in] custom_claims The optional custom claims list.
     * @param[in] custom_claims_length The number of custom claims.
     * @param[in] opt_params The optional plugin-specific input parameters.
     * @param[in] opt_params_size The size of opt_params in bytes.
     * @param[out] evidence_buffer An output pointer that will be assigned the
     * address of the evidence buffer.
     * @param[out] evidence_buffer_size A pointer that points to the size of the
     * evidence buffer in bytes.
     * @param[out] endorsements_buffer An output pointer that will be assigned
     * the address of the endorsements buffer.
     * @param[out] endorsements_buffer_size A pointer that points to the size of
     * the endorsements buffer in bytes.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*get_evidence)(
        oe_attester_t* context,
        uint32_t flags,
        const oe_claim_t* custom_claims,
        size_t custom_claims_length,
        const void* opt_params,
        size_t opt_params_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size,
        uint8_t** endorsements_buffer,
        size_t* endorsements_buffer_size);

    /**
     * Frees the generated attestation evidence and endorsements.
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] evidence_buffer A pointer to the evidence buffer.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (
        *free_evidence)(oe_attester_t* context, uint8_t* evidence_buffer);

    /**
     * Frees the generated attestation endorsements.
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] endorsements_buffer A pointer to the endorsements buffer.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*free_endorsements)(
        oe_attester_t* context,
        uint8_t* endorsements_buffer);
};
```

Here is the rationale for each element in the plugin struct:
- `base`
  - The base attestation role struct is required for each role.
- `get_evidence`, `free_evidence`, and  `free_endorsements`
  - Producing evidence and endorsements is necessary for attestation.
  - `flags` field to determine local vs. remote attestation.
  - There is a `custom_claims` parameter because many attestation protocols
    require the enclave to sign some data from a relying party. For example,
    many protocols follow the "challenge response" architecture, which requires
    the enclave to sign a nonce from the relying party.
  - There is an `opt_params` field because some plugins might require plugin
    specific input. For example, the SGX local attestation needs the
    other enclave's target info struct.
  - There is an `evidence_buffer` parameter to return the evidence.
  - There is an `endorsements_buffer` parameter to return the endorsements that are
    coupled with the evidence to ensure that the evidence and endorsements are
    in sync.

### Verifier Plugin API (Supported by host and enclave side)

The plugin API is very similar to the attester plugin. The only difference
is that it implements a `verify_evidence` function instead of `get_evidence`.

```C
/**
 * The verifier attestion role. The verifier is reponsible for verifying the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_verifier oe_verifier_t;
struct _oe_verifier
{
    /**
     * The base attestation role containing the common functions for each role.
     */
    oe_attestation_role_t base;

    /**
     * Verifies the attestation evidence and returns the claims contained in
     * the evidence.
     *
     * Each plugin must return the following required claims:
     *  - id_version (uint32_t)
     *      - Version number. Must be 1.
     *  - security_version (uint32_t)
     *      - Security version of the enclave. (ISVN for SGX).
     * - attributes (uint64_t)
     *      - Attributes flags for the evidence:
     *          - OE_REPORT_ATTRIBUTES_DEBUG: The evidence is for a debug
     * enclave.
     *          - OE_REPORT_ATTRIBUTES_REMOTE: The evidence can be used for
     * remote attestation.
     * - unique_id (uint8_t[32])
     *      - The unique ID for the enclave (MRENCLAVE for SGX).
     * - signer_id (uint8_t[32])
     *      - The signer ID for the enclave (MRSIGNER for SGX).
     * - product_id (uint8_t[32])
     *      - The product ID for the enclave (ISVPRODID for SGX).
     * - validity_from (oe_datetime_t)
     *      - Overall datetime from which the evidence and endorsements are
     *        valid.
     * - validity_until (oe_datetime_t)
     *      - Overall datetime at which the evidence and endorsements expire.
     * - plugin_uuid (uint8_t[16])
     *      - The UUID of the plugin used to verify the evidence.
     *
     * The plugin is responsible for handling endianness and ensuring that the
     * data from the raw evidence converted properly for each platform.
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[in] evidence_buffer The evidence buffer.
     * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
     * @param[in] endorsements_buffer The endorsements buffer.
     * @param[in] endorsements_buffer_size The size of endorsements_buffer in
     * bytes.
     * @param[in] policies A list of policies to use.
     * @param[in] policies_size The size of the policy list.
     * @param[out] claims The list of returned claims.
     * @param[out] claims_length The number of claims.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*verify_evidence)(
        oe_verifier_t* context,
        const uint8_t* evidence_buffer,
        size_t evidence_buffer_size,
        const uint8_t* endorsements_buffer,
        size_t endorsements_buffer_size,
        const oe_policy_t* policies,
        size_t policies_size,
        oe_claim_t** claims,
        size_t* claims_length);

    /**
     * Frees the generated claims.
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[out] claims The list of returned claims.
     * @param[out] claims_length The number of claims.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*free_claims_list)(
        oe_verifier_t* context,
        oe_claim_t* claims,
        size_t claims_length);
};
```

Here is the rationale for the parameters in the `verify_evidence` function:
- `verify_evidence`
  - Verifying evidence and endorsements is essential for attestation.
  - `evidence_buffer` and `endorsements_buffer` are inputs to the verification
    function.
  - Evidence can be verified according to some policy, which is why there
    is a `policies` parameter.
  - The `claims` field contains key-value pairs that can be verified by the
    caller. This will have the similar contents as the `oe_identity_t` field
    in the `oe_report_t` struct returned by `oe_verify_report` and any custom
    claims that were passed to the `get_evidence` function.
- `free_claims_list`
  - Since the claims list is returned by the plugin, the plugin must also provide
    a function for freeing the claims list.

###  Known Open Enclave Claims

- Each plugin's `verify_evidence` function must, at minimum, return the
  following claims (mapped from the `oe_identity_t`):
  
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
| plugin_uuid      | uuid_t             | The UUID of the plugin that generated the evidence.

### Built-in SGX Plugin

The current Open Enclave attestation only works on SGX platforms, so it will
be moved to an SGX plugin. Most of the current Open Enclave APIs can be mapped
directly to the plugin APIs. For the `on_register` and `on_unregister`  APIs,
they can simply be no-ops. `oe_get_report` can be mapped to the `get_evidence` API and
`oe_verify_report` can be mapped to the `verify_evidence` API.

### SGX Plug-In Implementation

The following provides a rough outline of how the SGX plugin will be implemented.

`sgx_plugin_attester.c`

```C
static
oe_result_t
sgx_attestation_plugin_on_register(
    oe_attester_t* plugin_context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_on_unregister(
    oe_attester_t* plugin_context)
{
    OE_UNUSED(plugin_context);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_get_evidence(
    oe_attester_t* plugin_context,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    OE_UNUSED(plugin_context);

    /*
     * Pseudocode description instead of actual C code:
     *
     * Hash custom claims field.
     * Call oe_get_report with the flags and opt_param parameters and the hash as reportdata.
     * Report contains the endorsements, so extract them out.
     * Evidence will be report + custom_claims blob.
     *
     * Note: Since the verifier can run outside the SGX enclave, it can be running on a
     * machine with different endianness. Consequently, it must be possible for the verifier
     * to determine the endianness of the multibyte numbers in the evidence and endorsements,
     * so it can properly interpret them.
     *
     */

    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_free_evidence(
    oe_attester_t* plugin_context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(plugin_context);
    free(evidence_buffer);
    return OE_OK;
}

static
oe_result_t
sgx_attestation_plugin_free_endorsements(
    oe_attester_t* plugin_context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(plugin_context);
    free(endorsements_buffer);
    return OE_OK;
}

/* Setting up the plugin structs. */
oe_attester_t sgx_attester_plugin = {
  .base = {
    .format_id = OE_SGX_PLUGIN_UUID,
    .on_register = sgx_attestation_plugin_on_register,
    .on_unregister = sgx_attestation_plugin_on_unregister,
  },
  .get_evidence = sgx_attestation_plugin_get_evidence,
  .free_evidence = sgx_attestation_plugin_free_evidence,
  .free_endorsements = sgx_attestation_plugin_free_endorsements
};

/* Implement helper initialization function. */
oe_attester_t* oe_sgx_plugin_attester() {
    return &sgx_attester_plugin;
}
```

`sgx_verifier_plugin.c`

```C
static
oe_result_t
sgx_attestation_plugin_on_register(
    oe_verifier_t* plugin_context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(plugin_context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_on_unregister(
    oe_verifier_t* plugin_context)
{
    OE_UNUSED(plugin_context);

    // Nothing to do
    return OE_OK;
}

static 
oe_result_t 
sgx_attestation_plugin_verify_evidence(
    oe_verifier_t* plugin_context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* polices,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    OE_UNUSED(plugin_context);

    /*
     * Pseudocode description instead of actual C code:
     *
     * Call oe_verify_report with all the input parameters and get the oe_identity_t back.
     * Look for the custom claims in the evidence header and extract them if found.
     * Verify the hash of custom claims == report data field in evidence report.
     * Convert oe_identity_t to the claims format.
     *
     * Note: Since the verifier can run outside the SGX enclave, it can be running on a
     * machine with different endianness. Consequently, the verification code needs to
     * understand the endianness of the multibyte numbers in the evidence and endorsements
     * and intelligently convert them to the verifier's native architecture.
     */

    return OE_OK;
}

static oe_result_t
sgx_attestation_plugin_free_claims_list(
    oe_verifier_t* plugin_context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(plugin_context);
    for (size_t i = 0; i < claims_length; i++)
    {
        free(claims[i].name);
        free(claims[i].value);
    }
    return OE_OK;
}

oe_verifier_t sgx_verifier_plugin = {
  .base = {
    .format_id = OE_SGX_PLUGIN_UUID,
    .on_register = sgx_attestation_plugin_on_register,
    .on_unregister = sgx_attestation_plugin_on_unregister,
  },
 .verify_evidence = sgx_attestation_plugin_verify_evidence,
 .free_claims_list = sgx_attestation_plugin_free_claims_list
};

oe_verifier_t* oe_sgx_plugin_verifier() {
    return &sgx_verifier_plugin;
}
```

These two headers will be exposed publicly, so the end user can easily create the SGX plugins.

`include/openenclave/attestation/sgx/attester.h`

```C
/**
 *  The `opt_params` field for `oe_get_evidence` identical to the `opt_params`
 *  field `oe_get_report`. In other words, it is the output of
 * `oe_get_target_info` for local attestation and is ignored for remote
 *  attestation.
 */
typedef void* oe_sgx_plugin_opt_params;

/**
 * Helper function that returns the SGX attester that can then be sent to
 * `oe_register_attester`.
 *
 * @retval A pointer to the SGX attester. This function never fails.
 */
oe_attester_t* oe_sgx_plugin_attester(void);
```

`include/openenclave/attestation/sgx/verifier.h`

```C
/**
 * Helper function that returns the SGX verifier that can then be sent to
 * `oe_register_verifier`.
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_verifier(void);
```

### New Open Enclave APIs

The functions are what the plugin user calls to use a plugin. They map almost
exactly to the plugin API. The main difference is that `oe_get_evidence`
requires the UUID of the plugin as an input parameter.

```C
/**
 * oe_register_attester
 *
 * Registers a new attester plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 *
 * This is available in the enclave and host.
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this will
 * not copy the contents of the pointer, so the pointer must be kept valid until
 * the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 */
oe_result_t oe_register_attester(
    oe_attester_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_register_verifier
 *
 * Registers a new verifier plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 *
 * This is available in the enclave and host.
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this will
 * not copy the contents of the pointer, so the pointer must be kept valid until
 * the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 */
oe_result_t oe_register_verifier(
    oe_verifier_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_unregister_attester
 *
 * Unregisters an attester plugin. This is available in the enclave and host.
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_unregister_attester(
    oe_attester_t* plugin);

/**
 * oe_unregister_verifier
 *
 * Unregisters an verifier plugin. This is available in the enclave and host.
 * 
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_unregister_verifier(
    oe_verifier_t* plugin);

/**
 * oe_get_evidence
 *
 * Generates the attestation evidence for the given UUID attestation format.
 * This function is only available in the enclave.
 *
 * @param[in] evidence_format_uuid The UUID of the plugin.
 * @param[in] flags Specifying default value (0) generates evidence for local
 * attestation. Specifying OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION generates
 * evidence for remote attestation.
 * @param[in] custom_claims The optional custom claims list.
 * @param[in] custom_claims_length The number of custom claims.
 * @param[in] opt_params The optional plugin-specific input parameters.
 * @param[in] opt_params_size The size of opt_params in bytes.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer in bytes.
 * @param[out] endorsements_buffer An output pointer that will be assigned the
 * address of the endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer in bytes.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_get_evidence(
    const uuid_t* evidence_format_uuid,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * oe_free_evidence
 *
 * Frees the attestation evidence. This function is only available in the
 * enclave.
 *
 * @param[in] evidence_buffer A pointer to the evidence buffer.
 * @retval OE_OK The function succeeded.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_evidence(uint8_t* evidence_buffer);

/**
 * oe_free_endorsements
 *
 * Frees the generated attestation endorsements. This function is only available
 * in the enclave.
 *
 * @param[in] endorsements_buffer A pointer to the endorsements buffer.
 * @retval OE_OK The function succeeded.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer);

/**
 * oe_verify_evidence
 *
 * Verifies the attestation evidence and returns well known and custom claims.
 * This is available in the enclave and host.
 *
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] endorsements_buffer The endorsements buffer.
 * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
 * @param[in] policies A list of policies to use.
 * @param[in] policies_size The size of the policy list.
 * @param[out] claims The list of claims.
 * @param[out] claims_length The length of the claims list.
 * @retval OE_OK on success.
 */
oe_result_t oe_verify_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

/**
 * oe_get_registered_attester_format_ids
 *
 * Get the unique identifiers of all registered attesters.
 *
 * @param[out] format_ids The list of the UUIDs of the registered attesters.
 * @param[out] format_ids_length The length of the UUIDs list.
 * @retval OE_OK on success.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_get_registered_attester_format_ids(
    oe_uuid_t** format_ids,
    size_t* format_ids_length);

/**
 * oe_get_registered_verifier_format_ids
 *
 * Get the unique identifiers of all registered verifiers.
 *
 * @param[out] format_ids The list of the UUIDs of the registered verifiers.
 * @param[out] format_ids_length The length of the UUIDs list.
 * @retval OE_OK on success.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_get_registered_verifier_format_ids(
    oe_uuid_t** format_ids,
    size_t* format_ids_length);

/**
 * oe_free_format_ids
 *
 * Frees the attester/verifier format ids.
 *
 * @param[in] format_ids The list of the attester/verifier UUIDs.
 * @retval OE_OK on success.
 */
oe_result_t oe_free_format_ids(oe_uuid_t* format_ids);

/**
 * oe_free_claims_list
 *
 * Frees a claims list.
 *
 * @param[in] claims The list of claims.
 * @param[in] claims_length The length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin that generated the claims does not exist or
 * has not been registered, so the claims can't be freed.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_claims_list(oe_claim_t* claims, size_t claims_length);
```

The outputs returned by `oe_get_evidence` will begin with the header
specified below. This allows `oe_verify_evidence` to determine what plugin
verification routine to use. Note that since these functions return opaque
structures, these headers are internal and not visible to the SDK consumers
or the plugin writers.

```C
/*
 * Header will be sent to oe_verify_evidence but not to the
 * plugin verification routines.
 */
typedef struct _oe_attestation_header
{
    /* Set to + 1 of existing header version. */
    uint32_t version;

    /* UUID to identify format. */
    uuid_t format_id;

    /* Size of evidence/endorsements sent to the plugin. */
    uint32_t data_size;

    /* The actual data */
    uint8_t data[];

    /* data_size bytes that follows the header will be sent to a plugin. */
} oe_attestation_header_t;
```

### Backwards compatibility

The new APIs should support verifying the old Open Enclave reports
generated by `oe_get_report`. The `oe_attestation_header_t` structure
shares the same 1st field (`uint32_t version`) as the old Open Enclave
report header. Consequently, the `oe_verify_evidence` can use this
information to decide if it needs to call a plugin or run the legacy
verification routine (which is technically the same logic as the SGX plugin).

User Experience
---------------

### Plug-in

There are two types of users: the plugin writers and the plugin consumers.

Plugin writers will implement their plugin according to the plugin API.
They should also provide a helper function that makes it easy for plugin
consumers to register the plugin as shown below:

`my_plugin_guid.h`

```C
/* Define the uuid. */
#define MY_PLUGIN_UUID                  \
{                                       \
 0x13, 0x99, 0x9a, 0xe5,                \
 0x23, 0xbe,                       _     \
 0x4f, 0xd4,                            \
 0x86, 0x63,                            \
 0x42, 0x1e, 0x3a, 0x57, 0xa0, 0xa4}    \
}
```

`my_plugin_attester.h`

```C
#include <my_plugin_guid.h>

/* Helper function to create the plugin. */
oe_attester_t* my_plugin_attester();

/* Example struct used for config data for my_plugin->on_register. */
struct my_plugin_attester_config_data_t { ... };

/* Example struct used as input parameters for my_plugin->get_evidence. */
struct my_plugin_attester_opt_params_t { ... };
```

`my_plugin_verifier.h`

```C
#include <my_plugin_guid.h>

/* Helper function to create the plugin. */
oe_verifier_t* my_plugin_verifier();

/* Example struct used for config data for my_plugin->on_register. */
struct my_plugin_verifier_config_data_t { ... };
```

`my_plugin_attester.c`

```C
#include <my_plugin_attester.h>

/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(
    oe_attester_t* context,
    const void* config_data,
    size_t config_data_size)
{
    struct my_plugin_config_data_t* my_data = (struct my_plugin_config_data_t*) config_data;
    /* Do meaningful work with my_data here. */
    return OE_OK;
}

static oe_result_t my_plugin_on_unregister(...) { ... }
static oe_result_t my_plugin_get_evidence(...) { ... }
static oe_result_t my_plugin_free_evidence(...) { ... }
static oe_result_t my_plugin_free_endorsements(...) { ... }

/* Setting up the plugin struct. */
oe_attester_t my_plugin = {
  .base = {
    .format_id = MY_PLUGIN_UUID,
    .on_register = my_plugin_on_register,
    .on_unregister = my_plugin_on_unregister,
  },
 .get_evidence = my_plugin_get_evidence,
 .free_evidence = my_plugin_free_evidence,
 .free_endorsements = my_plugin_free_endorsements
};

/* Implement helper initialization function. */
oe_attester_t* my_plugin_attester() {
    return &my_plugin;
}
```

`my_plugin_verifier.c`

```C
#include <my_plugin_verifier.h>

/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(...) { ... }
static oe_result_t my_plugin_on_unregister(...) { ... }
static oe_result_t my_plugin_verify_evidence(...) { ... }
static oe_result_t my_plugin_free_claims_list(...) { ... }

/* Setting up the plugin struct. */
oe_verifier_t my_plugin = {
  .base = {
    .format_id = MY_PLUGIN_UUID,
    .on_register = my_plugin_on_register,
    .on_unregister = my_plugin_on_unregister,
   },
 .verify_evidence = my_plugin_verify_evidence,
 .free_claims_list = my_plugin_free_claims_list
};

/* Implement helper initialization function. */
oe_verifier_t* my_plugin_attester() {
    return &my_plugin;
}
```

They can then compile their code in the standard way for building Open Enclave
enclave and host applications.

Plugin consumers will use the new "plugin aware" APIs like
`oe_get_evidence`. The enclave can generate the evidence
using the plugin like this:

`attester.c`

```C
#include <my_plugin_attester.h>

/* Register plugin. Send the config data if necessary. */
struct my_plugin_attester_config_data_t config = { ... };
size_t config_size = sizeof(config);
oe_register_attester(my_plugin_attester(), &config, config_size);

/* Create input params struct if needed. */
struct my_plugin_attester_opt_params_t params = { ... };
size_t params_size = sizeof(params);

/* Create claims if desired. */
oe_claim_t claims = { ... };
size_t claims_size = ...;

/* Get evidence. */
oe_get_evidence(
    MY_PLUGIN_UUID,
    OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION,
    claims,
    claims_size,
    &params,
    params_size,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);

/* Send the evidence to the verifier. Protocol is up to enclave and verifier. */
send(VERIFIER_SOCKET_FD, evidence, evidence_size, 0);
send(VERIFIER_SOCKET_FD, endorsements, endorsements_size, 0);

/* Free data and unregister plugin. */
oe_free_evidence(evidence);
oe_free_endorsements(endorsements);
oe_unregister_attester(my_plugin_attester());
```

The verifier, which can either be the enclave or the host, can verify the evidence like this:

`verifier.c`

```C
#include <my_plugin_verifier.h>

/* Register plugin. Send the config data if necessary. */
struct my_plugin_verifier_config_data_t config = { ... };
size_t config_size = sizeof(config);
oe_register_verifier(my_plugin_verifier(), &config, config_size);

/* Receive evidence and endorsement buffer from enclave. */
recv(ENCLAVE_SOCKET_FD, evidence, evidence_size, 0);
recv(ENCLAVE_SOCKET_FD, endorsements, endorsements_size, 0);

/* Set polices if desired. */
oe_datetime_t time = { ... };
oe_policy_t policy = {
    .type = OE_POLICY_ENDORSEMENTS_TIME,
    .policy = &time,
    .policy_size = sizeof(time);
};

/* Verify evidence. Can check the claims if desired. */
oe_verify_evidence(
    evidence,
    evidence_size,
    endorsements,
    endorsements_size,
    &policy,
    1,
    &claims,
    &claims_size);

/* Free data and unregister plugin. */
oe_free_claims_list(claims, claims_size);
oe_unregister_verifier(my_plugin_verifier());
```

In either case, the plugin user can link in the plugin to build their app:

```bash
gcc -o my_app_attester attester.o my_plugin_attester.o ...
gcc -o my_app_verifier verifier.o my_plugin_verifier.o ...
```

Alternate Designs Considered
----------

Another option is to transform the Open Enclave report from a platform-specific
opaque blob to something like a JWT/CWT token or X.509 cert, which contains
platform-specific attestation data embedded inside it. This makes it easy to add
or parse claims and extend the report format. However, users would be constrained
to the format chosen by Open Enclave and they will not be able to use their own
custom format.

Authors
-------

Name: Akash Gupta

Email: akagup@microsoft.com

Github username: gupta-ak
