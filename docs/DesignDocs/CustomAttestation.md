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

However, for some developers, these APIs are too inflexible for their
attestation requirements. For example, one might want to extend Open Enclave's
current attestation structures with extra information, such as geolocation
or a timestamp. Another user might want their enclaves to generate attestation
data that is in a compatible format with their existing authentication
infrastructure, such as a JSON Web Token or a X509 certificate. There are also
users who want to specify their collaterals (information from a second source
used for verification), instead of using the set of collaterals provided by Open
Enclave.

Overall, there has been interest in enhancing Open Enclave's APIs to support
custom attestation formats to enable these scenarios.

Terminology
-----------

This document uses the following terminology defined here:

- Claims
  - Claims are statements about a particular subject. They consist of
    name-value pairs containing the claim name, which is a string, and
    claim value, which is arbitrary data. Example of claims could be
    [key="version", value=1] or [key="enclave_id", value=1111].
- Evidence
  - This is the data about the enclave that is produced and signed by it.
    The SGX report would be an example of evidence.
- Collateral
  - This is additional data that used in the evidence verification process,
    but is not produced by the enclave. An example of collateral would be
    the quoting enclave's identity, which is for SGX remote attestation and
    is retrieved from Intel's servers, rather than the enclave.
- Verifier
  - The verifier is responsible for taking in the evidence and collateral
    and deciding if the enclave is trustworthy.
- Relying party
  - The relying party is the entity interested in communicating with an
    enclave. The enclave must attest to the relying party before the
    relying party can trust it. The relying party can also play the role
    of the verifier, but it does not necessarily have to.

Specification
-------------

To support custom attestation formats, this document proposes adding a plugin
model for attestation. The Open Enclave SDK will define a set of common APIs
that each plugin must implement. Each plugin will define a random UUID to
distinguish it from other plugins.

Futhermore, there will be additional attestation "plugin aware" APIs that are
analogous to `oe_get_report` and `oe_verify_report`, along with functions for
registering and unregistering plugins. The user can statically link in their
desired plugin and call the register plugin function. The attestation data can
be retrieved from the "plugin aware" analogue of `oe_get_report` with the
desired UUID. The generated data will have the UUID in its header. The user can
call the analogue of `oe_verify_report` to verify the data and the Open Enclave
runtime can use this UUID to determine what plugin verification routine to run.

### Plugin API

Each plugin must implement the functions below:

```C
/**
 * Struct that defines the structure of each plugin. Each plugin must
 * define an UUID for its format and implement the functions in this
 * struct. Ideally, each plugin should provide a helper function to
 * create this struct on the behalf of the plugin users.
 */
struct oe_attestaton_plugin_t
{
    /**
     * The UUID for the plugin.
     */
    uuid_t format_id;

    /**
     * The function that gets executed when a plugin is registered.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] config_data An optional pointer to the configuration data.
     * @param[in] config_data_size The size in bytes of config_data.
     * @retval OE_OK on success.
     */
    oe_result_t (*on_register)(
        oe_attestaton_plugin_t* plugin_context,
        const void* config_data,
        size_t config_data_size);

    /**
     * The function that gets executed when a plugin is unregistered.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @retval OE_OK on success.
     */
    oe_result_t (*on_unregister)(
        oe_attestaton_plugin_t* plugin_context);

    /**
     * Generates the attestation evidence, which is defined as the data
     * produced by the enclave. The caller may pass in custom claims, which
     * must be attached to the evidence and then cryptographically signed.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] custom_claims A buffer to the optional custom claims.
     * @param[in] custom_claims_size The size in bytes of custom_claims.
     * @param[out] evidence_buffer An output pointer that will be assigned the
     * address of the evidence buffer.
     * @param[out] evidence_buffer_size A pointer that points to the size of the
     * evidence buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*get_evidence)(
        oe_attestaton_plugin_t* plugin_context,
        const uint8_t* custom_claims,
        size_t custom_claims_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size);

    /**
     * Frees the generated attestation evidence.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] evidence_buffer A pointer to the evidence buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*free_evidence)(
        oe_attestaton_plugin_t* plugin_context,
        uint8_t* evidence_buffer);

    /**
     * Generates the attestation collateral, which is defined as the data
     * produced outside of the enclave that is used part of the verification
     * process.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[out] collateral_buffer An output pointer that will be assigned the
     * address of the collateral buffer.
     * @param[out] collateral_buffer_size A pointer that points to the size of the
     * collateral buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*get_collateral)(
        oe_attestaton_plugin_t* plugin_context,
        uint8_t** collateral_buffer,
        size_t* collateral_buffer_size);

    /**
     * Frees the generated attestation collateral.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] collateral_buffer A pointer to the collateral buffer.
     * @retval OE_OK on success.
     */
    oe_result_t (*free_collateral)(
        oe_attestaton_plugin_t* plugin_context,
        uint8_t* collateral_buffer);

    /**
     * Verifies the attestation evidence and returns the claims contained in
     * the evidence.
     *
     * @param[in] plugin_context A pointer to the attestation plugin struct.
     * @param[in] evidence_buffer The evidence buffer.
     * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
     * @param[in] collateral_buffer The collateral buffer.
     * @param[in] collateral_buffer_size The size of collateral_buffer in bytes.
     * @param[out] claims The list of claims.
     * @param[out] claims_size The size of claims.
     * @retval OE_OK on success.
     */
    oe_result_t (*verify_evidence)(
        oe_attestaton_plugin_t* plugin_context,
        const uint8_t* evidence_buffer,
        size_t evidence_buffer_size,
        const uint8_t* collateral_buffer,
        size_t collateral_buffer_size,
        uint_t** claims,
        size_t* claims_size);
};
```

Here is the rationale for each element in the plugin struct:

- `format_id`
  - Each plugin needs an unique identifier to distinguish itself.
- `on_register` and `on_unregister`
  - A plugin might require some setup or teardown when it is registered or
    unregistered, so these functions are required. Furthermore, a plugin
    might require configuration, which is why there is a `config_data`
    parameter. The configuration data can be plugin specific, so no format is
    specified in this proposal.
- `get_evidence` and `free_evidence`
  - Producing evidence is necessary for attestation.
  - There is a `custom_claims` parameter because many attestation protocols
    require the enclave to sign some claim from a relying party. For example,
    many protocols follow the "challenge response" architecture, which requires
    the enclave to sign a nonce from the relying party.
- `get_collateral` and `free_collateral`
  - Producing collateral is essential for attestation.
  - Examples of collateral could be firmware measurements from the device's
    manufacturer or a certificate revocation list (CRL) from an X509 certificate.
- `verify_evidence`
  - Verifying evidence and collateral is essential for attestation.
  - The `claims` field contains key-value pairs that can be verified by the
    caller. This will have the similar contents as the `oe_identity_t` field
    in the `oe_report_t` struct returned by `oe_verify_report` and any custom
    claims that were passed to the `get_evidence` function.
  - Should at minimum have the following claims (based of `oe_identity_t`):
    - `id_version`: Version of the OE claims. Must be 0.
    - `security_version`: Security version of the enclave. (ISVN for SGX).
    - `attributes`: Values of the attributes flags for the enclave:
      - `OE_REPORT_ATTRIBUTES_DEBUG`: The report is for a debug enclave.
      - `OE_REPORT_ATTRIBUTES_REMOTE`: The report can be used for remote
        attestation.
    - `unique_id`: The unique ID for the enclave (MRENCLAVE for SGX).
    - `signer_id`: The signer ID for the enclave (MRSIGNER for SGX).
    - `product_id`: The product ID for the enclave (ISVPRODID for SGX).

Open Issues:

- Format of claims.
  - The format should be independent of the plugin. It also should be easy
    to extract the claims to chain plugins. For example, an app might use
    plugin A to verify evidence A and extract the claims. Then, it might
    use those claims as the `custom_claims` parameter to plugin B's
    `get_evidence` function. If the format of the claims is something like
    JSON or CBOR, then the idea of chaining claims could work.
- Input parameters for `get_evidence`, `get_collateral` and `verify_evidence`.
  - For `get_evidence`, there could potentially be 3 types of input:
    1. Input to the function itself.
    2. Custom claims that are known to the plugin.
    3. Custom claims that are unknown to the plugin and should be treated as a
    opaque block.

    The current API proposal has no way to distinguish all 3.
    Likewise, `get_collateral` and `verify_evidence` could require function
    input parameters. A solution could be having a structured way to define
    these parameters using JSON or CBOR.

### New SGX Plugin

The current Open Enclave attestation only works on SGX platforms, so it will
be moved to an SGX plugin. Most of the current Open Enclave APIs can be mapped
directly to the plugin APIs. For the `on_register` APIs, they can simply be
no-ops. `oe_get_report` can be mapped to the `get_evidence` API and
`oe_verify_report` can be mapped to the `verify_evidence` API.

The only thing that can't be mapped is the collaterals API, since the current
Open Enclave implementation doesn't have an API that exposes the collaterals.
Thus, this plugin work is dependant on @jazzybluesea's collateral work.

### New Open Enclave APIs

The functions are what the plugin user calls to use a plugin. They map almost
exactly to the plugin API. The main difference is that
`oe_get_attestation_evidence` and `oe_get_attestation_collateral` require the
UUID of the plugin as an input parameter.

```C
/**
 * oe_register_attestation_plugin
 *
 * Registers a new attestation plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that will
 * not copy the contents of the pointer, so the pointer must be kept valid until
 * the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 */
oe_result_t oe_register_attestation_plugin(
    oe_attestaton_plugin_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_unregister_attestation_plugin
 *
 * Unregisters an attestation plugin.
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_unregister_attestation_plugin(
    oe_attestaton_plugin_t* plugin);

/**
 * oe_get_attestation_evidence
 *
 * Generates the attestaton evidence for the given UUID attestation format.
 *
 * @param[in] evidence_format_uuid The UUID of the plugin.
 * @param[in] custom_claims Optional custom claims that will be attached and
 * cryptographically tied to the plugin evidence.
 * @param[in] custom_claims_size The size in bytes of custom_claims
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_get_attestation_evidence(
    const uuid_t* evidence_format_uuid,
    const uint8_t* custom_claims,
    size_t custom_claims_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size);

/**
 * oe_free_attestation_evidence
 *
 * Frees the attestation evidence.
 *
 * @param[in] evidence_buffer A pointer to the evidence buffer.
 */
void oe_free_attestation_evidence(uint8_t* evidence_buffer);

/**
 * oe_get_attestation_collateral
 *
 * Generates the attestaton collateral for the given UUID attestation format.
 *
 * @param[in] evidence_format_uuid The UUID of the plugin.
 * @param[out] collateral_buffer An output pointer that will be assigned the
 * address of the collateral buffer.
 * @param[out] collateral_buffer_size A pointer that points to the size of the
 * collateral buffer.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin does not exist.
 */
oe_result_t oe_get_attestation_collateral(
    const uuid_t* evidence_format_uuid,
    uint8_t** collateral_buffer,
    size_t* collateral_buffer_size);

/**
 * oe_free_attestation_collateral
 *
 * Frees the attestation collateral.
 *
 * @param[in] collateral_buffer A pointer to the collateral buffer.
 */
void oe_free_attestation_collateral(uint8_t* collateral_buffer);

/**
 * oe_verify_attestation_evidence
 *
 * Verifies the attestation evidence and returns well known and custom claims.
 *
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] collateral_buffer The collateral buffer.
 * @param[in] collateral_buffer_size The size of collateral_buffer in bytes.
 * @param[out] claims The list of claims.
 * @param[out] claims_size The size of claims.
 * @retval OE_OK on success.
 */
oe_result_t oe_verify_attestation_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* collateral_buffer,
    size_t collateral_buffer_size,
    uint_t** claims,
    size_t* claims_size);
````

The output returned by the `oe_get_attestation_collateral` and
`oe_register_attestation_plugin` functions will begin with the header
specified below. This allows `oe_verify_attestation_evidence` to
determine what plugin verification routine to use. Note that since these
functions return opaque structures, these headers are internal and not visible
to the SDK consumers or the plugin writers.

```C
/*
 * Header will be sent to oe_verify_attestation_evidence but not to the
 * plugin verification routines.
 */
typedef struct _oe_attestation_header
{
    /* Set to + 1 of existing header version. */
    uint32_t version;

    /* UUID to identify format. */
    uuid_t format_id;

    /* Size of evidence/collateral sent to the plugin. */
    uint32_t data_size;

    /* data_size bytes that follows the header will be sent to a plugin. */
} oe_attestation_header_t;
```

### Backwards compatibility
The new APIs should support verifying the old Open Enclave reports
generated by `oe_get_report`. The `oe_attestation_header_t` structure
shares the same 1st field (`uint32_t version`) as the old Open Enclave
report header. Consequently, the `oe_verify_attestation_evidence` can use this
information to decide if it needs to call a plugin or run the legacy
verification routine (which is technically the same logic as the SGX plugin).

The legacy `oe_get_report` and `oe_verify_report` APIs can be deprecated,
since their functionality would be superseded by these new APIs.

User Experience
---------------

There are two types of users: the plugin writers and the plugin consumers.

Plugin writers will implement their plugin according to the plugin API.
They should also provide a helper function that makes it easy for plugin
consumers to register the plugin as shown below:

`my_plugin.h`
```C
oe_attestation_plugin_t* my_plugin();

/* Define the uuid. */
#define MY_PLUGIN_UUID                  \
{                                       \
 0x13, 0x99, 0x9a, 0xe5,                \
 0x23, 0xbe,                            \
 0x4f, 0xd4,                            \
 0x86, 0x63,                            \
 0x42, 0x1e, 0x3a, 0x57, 0xa0, 0xa4}    \
}
```

`my_plugin.c`
```C
/* Plugin implementation functions here. */
static oe_result_t my_plugin_on_register(...) {...}

/* Setting up the plugin struct. */
oe_attestation_plugin_t my_plugin = {
 /* Plugin UUID. */
 .format_id = MY_PLUGIN_UUID,

  /* Plugin functions. */
 .on_register = my_plugin_on_register,
  /* Rest of the plugin functions. */
};

/* Implement helper initialization function. */
oe_attestation_plugin_t my_plugin() {
    return &my_plugin;
}
```

They can then compile their code in the standard way for building Open Enclave
enclave and host applications.

Plugin consumers will use the new "plugin aware" APIs like
`oe_get_attestation_evidence`. Plugin consumers will use the APIs like this:

use_plugin.c
```C
#include <my_plugin.h> // For my_plugin() helper function and UUID.

/* Register plugin. Send the config data if necessary. */
oe_register_plugin(my_plugin(), my_config_data, my_config_data_size);

/* Get evidence. */
oe_get_attestation_evidence(
    MY_PLUGIN_UUID,
    my_custom_claims,
    my_custom_claims_size,
    &evidence,
    &evidence_size);

/* Get collateral. */
oe_get_attestation_collateral(
    MY_PLUGIN_UUID,
    &collateral,
    &collateral_size);

/* Verify evidence. Can check the claims if desired. */
oe_verify_attestaton_evidence(
    evidence,
    evidence_size,
    collateral,
    collateral_size,
    &claims,
    &claims_size);

/* Unregister plugin. */
oe_unregister_plugin(my_plugin());

```

The plugin user can now link in the plugin to build their app:

```bash
gcc -o my_app use_plugin.o my_plugin.o ...
```

Alternates
----------

Another option is to transform the Open Enclave report from a platform-specific
opaque blob to something like a JWT/CWT token or X509 cert, which contains
platform-specific attestation data embedded inside it. This makes it easy to add
or parse claims and extend the report format. However, users would be constrained
to the format chosen by Open Enclave and they will not be able to use their own
custom format.

Authors
-------

Name: Akash Gupta

Email: akagup@microsoft.com

Github username: gupta-ak
