Proposal of OE SDK Attestation Public and Plugin API for V0.1x Release
====

# Introduction

This document describes the proposed OE SDK attestation public and plugin API
for V0.1x release, as an evolution of the experimental attestation API
implemented in the
[OE SDK V0.9 release](https://github.com/openenclave/openenclave/tree/v0.9.x).

This proposal is based on these efforts:
- Design document [Attestation V3 Update]:
[Custom Attestation Data Formats for Open Enclave V3 Updates](CustomAttestation_V3.md).
- Discussion in [Issue #2729]: [Outstanding issues on attestation plugin design](https://github.com/openenclave/openenclave/issues/2729).
- Proposal to add attestation evidence format support [[PR #3089](https://github.com/openenclave/openenclave/pull/3089)].
- Design document [quote-ex Integration]:
[Attestation: OE SDK Integration with Intel® SGX SDK quote-ex Library for Generation of Evidence in New Formats](SGX_QuoteEx_Integration.md).
- Design document [Design Notes]:
[Notes on OE SDK Attestation API and Plugin Library Design](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md).
  - Note: this document is in the process of being up-streamed as OE SDK [PR #2801](https://github.com/openenclave/openenclave/pull/2801).
- IETF draft [RATS Arch]
[Remote Attestation Procedures Architecture](https://tools.ietf.org/html/draft-ietf-rats-architecture)

Note: the proposed API and plugin design will continue to be marked as
"experimental", to have the flexibility for further improvements in future
releases.

# OE SDK Attestation Public API Proposal

Note: in the RATS model as described in the
[[RATS Arch]](https://tools.ietf.org/html/draft-ietf-rats-architecture)
document, there are three roles: an Attester, a Verifier, and a Relying Party.
The OE SDK attestation stack V0.1x does not try to provide a complete implementation of
these roles, nor try to provide means for secure communication between them.
The OE SDK attestation stack implements basic functionalities for evidence
generation and verification, and exposes these functionalities to applications
via a set of public API functions. Application software can use this public API
to implement complete RATS Attester and Verifier roles. The application software
is also responsible to convert the evidence verification results into signed
Attestation Results for consumption by a Relying Party role, if this role is
not in the same security domain as the Verifier role. But the proposed API
readily supports applications functioning as a composite device implementing
both the Verifier and Relying Party roles in the same security domain, since
in this case the Attestation Results passed from the Verifier role to the
Relying Party role do not need to be signed.

## Existing OE SDK V0.9 Public API

The OE SDK V0.9 experimental public API for attestation is composed of
functions for a number of use cases to be implemented by applications.
The use cases fall into two categories: evidence generation and verification.

Use cases for evidence generation:

- Retrieve a single SGX attester plugin.
  - Function `oe_attester_t* oe_sgx_plugin_attester(void)`,
  declared in header file [openenclave/attestation/sgx/attester.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/sgx/attester.h).
  - It returns a single hardcoded SGX attester plugin for generation of
  evidence in SGX ECDSA-p256 (simply called ECDSA) format.
- Register an attester plugin.
  - Function `oe_result_t oe_register_attester(oe_attester_t* plugin, const void* config_data, size_t config_data_size)`, declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).
  - The attester plugin returned by `oe_sgx_plugin_attester()` can be
  registered with this function.
  - Note: requirement for the application to supply a plugin-specific `config_data`
  parameter is against the goal of a TEE-agnostic OE SDK API. More discussion on
  TEE agnostic design can be found in the
  [[Design Notes]](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md#attester--verifier-security-model-and-tee-agnostic-design)
  document.
- Get evidence in a globally unique format, optionally along with a set of
endorsements.
  - Function `oe_result_t oe_get_evidence(const oe_uuid_t* format_id, uint32_t flags, const oe_claim_t* custom_claims_buffer, size_t custom_claims_buffer_length, const void* opt_params, size_t opt_params_size, uint8_t** evidence_buffer, size_t* vidence_buffer_size, uint8_t** endorsements_buffer, size_t* endorsements_buffer_size)`,
    declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).
  - Upon successful evidence generation, `oe_get_evidence()` returns the
  generated evidence in a dynamically allocated buffer. It also has the option
  to return a set of endorsements in another dynamically allocated buffer.
  After processing of the evidence and the endorsements, the caller is
  responsible to free these buffers.
  - The `flags` parameter is a legacy inherited from the legacy API
  `oe_get_report()` to indicate SGX local or remote attestation.
  It's redundant -- overlapping with the `format_id` parameter
  which identifies evidence formats with globally unique UUIDs.
  - Note: please see the "Semantics of Custom Claims and Optional Parameters"
  section of the
  [[Design Notes]](https://github.com/openenclave/openenclave/pull/2801)
  document for a discussion of the semantics
  of the `custom_claims_buffer` and `opt_params` parameters.
- Free a dynamically allocated evidence buffer.
  - Function `oe_result_t oe_free_evidence(uint8_t* evidence_buffer)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h)
- Free a dynamically allocated endorsements buffer.
  - Function `oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h)
- Unregister an attester plugin.
  - Function `oe_unregister_attester(oe_attester_t* plugin)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).

Use cases for evidence verification:

- Retrieve a single SGX verifier plugin.
  - Function `oe_verifier_t* oe_sgx_plugin_verifier(void)`, declared in header
  file [openenclave/attestation/sgx/verifier.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/sgx/verifier.h).
  - It returns a single hardcoded SGX verifier plugin for verification of
  evidence in SGX ECDSA format.
- Register a verifier plugin.
  - Function `oe_result_t oe_register_verifier(oe_verifier_t* plugin, const void* config_data, size_t config_data_size)`, declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).
  - The verifier plugin returned by `oe_sgx_plugin_verifier()` can be
  registered with this function.
  - See notes for the `oe_register_attester()` API function for explanation of
  the `config_data` parameter.
- Verify evidence, optionally using a set of input endorsements and policies.
  - Function `oe_result_t oe_verify_evidence(const uint8_t* evidence_buffer, size_t evidence_buffer_size, const uint8_t* endorsements_buffer, size_t endorsements_buffer_size, const oe_policy_t* policies, size_t policies_size, oe_claim_t** claims, size_t* claims_length)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).
  - Upon successful verification, `oe_verify_evidence` returns a list of claims
  in a dynamically allocated buffer. This list includes all the custom claims
  input to the call to `get_evidence()` that generated the verified evidence.
    - Note: in case a custom claim has the same name as a well-known base claim,
    the returned list does not have flags indicating which is base and which is
    custom.
- Free a dynamically allocated claims buffer.
  - Function `oe_result_t oe_free_claims_list(oe_claim_t* claims, size_t claims_length)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h)
- Unregister a verifier plugin.
  - Function `oe_unregister_verifier(oe_verifier_t* plugin)`,
  declared in header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).

The single supported SGX evidence format UUID, OE_SGX_PLUGIN_UUID for SGX
ECDSA format, is declared in header file
[openenclave/internal/sgx/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/internal/sgx/plugin.h).

In addition to the above plugin-based public API for attestation, the OE SDK
also supports legacy API for generation and verification of SGX reports:
`oe_get_report()` and `oe_verify_report()`.

Areas of improvement in the existing attestation public API:
- Attester and Verifier plugins are unnecessarily exposed to application
software
  - It's sufficient for application to use globally unique evidence format
  UUID in generation and verification of evidence.
  - Plugins are the artifact of the OE SDK attestation framework internal
  design that application software does not need to care.
- The API does not enable applications to discover which formats are supported
for evidence generation or verification.
- SGX specific functions are exposed as public API
- The public and plugin API declarations are all contained in a
single header file [openenclave/attestation/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h).
- For SGX, the globally unique UUIDs identify the evidence formats.
There is no need of local / remote flag.

## Proposed OE SDK V0.1x Public API

Objectives: address the areas of improvement in the existing public API.

- Separate public and plugin API declarations into different header files.
- Only expose evidence formats for evidence generation and verification.
There is no exposure of plugin design.
- Remove TEE specific API elements, e.g. SGX-specific functions
- Enable applications run-time discovery of supported formats for evidence
generation and verification in
[TEE-agnostic](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md#attester--verifier-security-model-and-tee-agnostic-design)
manner.
- Remove legacy artifacts that have become redundant, e.g. the SGX
local / remote flags.
- Incorporate changes proposed in [PR #3089](https://github.com/openenclave/openenclave/pull/3089).

Proposed Headers files:

- Attester public API to be declared in `<openenclave/attestation/attester.h>`
- Verifier public API to be declared in `<openenclave/attestation/verifier.h>`
- TEE-agnostic claim IDs to be declared in `<openenclave/bits/evidence.h>`
- SGX-specific evidence format UUIDs and claim IDs to be declared in
`<openenclave/attestation/sgx/evidence.h>`
- Plugin API (helper functions and plugin entry points) to be declared in
`<openenclave/internal/plugin.h>`
- SGX-specific plugin related names to be declared in
`<openenclave/internal/sgx/plugin.h>`

Use cases for evidence generation:

- Initialize attester environment.
  - Function `oe_result_t oe_attester_initialize(void)`.
  - Internally, the implementation enumerates and registers all
  attester plugins configured for the platform and the calling
  application.
  - This function is idempotent and can be called multiple times without
  adverse effect.
- Select an evidence format from a supplied list of formats.
  - Function `oe_result_t oe_attester_select_format(const oe_uuid_t* formats, size_t formats_length, oe_uuid_t* selected_format)`
  - The input list is treated as an ordered list, with descending priority
  order from left to right.
  - The implementation selects the left-most evidence format from the input
  list that is supported by one of the registered attester plugins. If there
  is no match, `OE_NOT_FOUND` is returned.
  - This function is defined in document
  [[Attestation V3 Update]](CustomAttestation_V3.md)
- Get evidence in an globally unique format, optionally along with a set of
endorsements.
  - Function `oe_result_t oe_get_evidence(const oe_uuid_t* format_id, uint32_t flags, const void* custom_claims_buffer, size_t custom_claims_buffer_size, const void* opt_params, size_t opt_params_size, uint8_t** evidence_buffer, size_t* evidence_buffer_size, uint8_t** endorsements_buffer, size_t* endorsements_buffer_size)`.
  - The `flags` parameter in the OE SDK V0.9 API release is redefined
  to be a bit-wise parameter. In the current version, there is one bit
  defined:
    - `OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID`: if this bit is set, the
  evidence and endorsements will be wrapped with a header containing the
  format ID.
  - The optional custom claims are input in a flat buffer. There is no
  restriction in how the caller structures its set of custom claims held
  in the buffer.
  - Otherwise, this function is the same as in the OE SDK V0.9 release.
    - Note: in documentation for the public API, the UUIDs should be described
    as identifiers of evidence formats and not of plugins.
- Free a dynamically allocated evidence buffer.
  - Function `oe_result_t oe_free_evidence(uint8_t* evidence_buffer)`.
  - The same definition as in the OE SDK V0.9 release.
- Free a dynamically allocated endorsements buffer.
  - Function `oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer)`.
  - The same definition as in the OE SDK V0.9 release.
- Shutdown attester environment.
  - Function `oe_result_t oe_attester_shutdown(void)`.
  - Internally, the implementation unregisters all attester plugins, and
  reclaims all resources allocated for them.
  - This function is idempotent and can be called multiple times without
  adverse effect.

Use cases for evidence verification:

- Initialize verifier environment.
  - Function `oe_result_t oe_verifier_initialize(void)`.
  - Internally, the implementation enumerates and registers all verifier plugins
  configured for the platform and the calling application.
  - This function is idempotent and can be called multiple times without
  adverse effect.
- Enumerate all evidence formats that can be verified.
  - Function `oe_result_t oe_verifier_get_formats(oe_uuid_t** formats, size_t* formats_length)`.
  - The returned evidence format list is held in a dynamically-allocated buffer
  - Every format in the returned list maps to at least one registered verifier
  plugin.
- Free a dynamically allocated format list buffer.
  - Function `oe_result_t oe_verifier_free_formats(oe_uuid_t* formats)`.
- Get the settings for verification of an evidence format.
  - Function `oe_result_t oe_verifier_get_format_settings(const oe_uuid_t* format, uint8_t** settings, size_t* settings_size)`.
  - For a given evidence format, get the settings for it in a dynamically
  allocated buffer. This settings will be passed to an attester as the
  `opt_params` parameter for evidence generation.
  - Note: similar to the function `oe_get_verifier_settings()` defined in
  document
  [[Attestation V3 Update]](CustomAttestation_V3.md).
- Free a dynamically allocated format settings buffer.
  - Function `oe_result_t oe_verifier_free_format_settings(uint8_t* settings)`
  - As defined in document
  [[Attestation V3 Update]](CustomAttestation_V3.md)
- Verify evidence, optionally with a set of endorsements and policies.
  - Function `oe_result_t oe_verify_evidence(const oe_uuid_t* format_id, const uint8_t* evidence_buffer, size_t evidence_buffer_size, const uint8_t* endorsements_buffer, size_t endorsements_buffer_size, const oe_policy_t* policies, size_t policies_size, oe_claim_t** claims, size_t* claims_length)`.
  - The optional parameter `format_id` is added.
    - If it is `NULL`, the `evidence_buffer` and `endorsements_buffer`
    must be wrapped with an attestation header that contains a valid
    format ID.
    - Otherwise, it must hold a valid format ID that identifies the
    type of evidence and endorsements data in the `evidence_buffer` and
    `endorsements_buffer` parameters. The data in these two buffers must not
    be wrapped with an attestation header.
  - Otherwise, this function has the same definition as in the OE SDK V0.9
  release.
- Free a dynamically allocated claims list buffer.
  - Function `oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length)`.
  - This function has the definition as in the OE SDK V0.9 release.
  - The claims list must have an claim of name `OE_CLAIM_UNIQUE_ID` with
  a value of the UUID of the evidence to which the claims belong.
- Shutdown verifier environment.
  - Function `oe_result_t oe_verifier_shutdown(void)`.
  - Internally, the implementation unregisters all verifier plugins, and
  reclaims all resources allocated for them.
  - This function is idempotent and can be called multiple times without
  adverse effect.

Discussion:

From application developers' point of view, the need to call API functions
`oe_attester_initialize()` and `oe_verifier_initialize()` sets a requirement
for an attester / verifier application to declare its intention to start using
the plugin-based attester / verifier API.

Internally, the OE SDK framework / plugin implementation of these API functions
can perform any tasks as needed to get the environment set up properly.
If resolution of
[issue #2903](https://github.com/openenclave/openenclave/issues/2903)
leads to a plugin design that performs all initialization internally,
at that time these functions can become NOP.

## Application Developer Experience

The user experience scenario 1 described in document
[[Attestation V3 Update]](CustomAttestation_V3.md)
is supported with minimum changes. In this scenario, a verifier provides
a list of evidence formats that it accepts to an attester, and the attester
selects from this list a single format to generate evidence.

- Verifier application:
    - Upon startup, initializes its verifier environment, with
    `oe_verifier_initialize()`.
    - Enumerates the list of evidence formats that it verifies,
    with `oe_verifier_get_formats()`.
    - Sends the accepted evidence format list to the attester application.
- Attester application:
    - Upon startup, initializes its attester environment, with
    `oe_attester_initialize()`.
    - Receives an evidence format list from the verifier application.
    - Selects an evidence format from the received list, with
    `oe_attester_select_format()`.
    - Sends the selected evidence format to the verifier application,
    for format-specific settings and custom claims.
- Verifier application:
    - Gets the settings for the received evidence format,
    with `oe_verifier_get_format_settings()`.
    - Generates additional parameters, e.g. nonce to ensure evidence
    freshness, as custom claims.
      - Note: this step is performed by the verifier application and does not
      involve invocation of any OE SDK API. See section "Semantics of Custom
      Claims and Optional Parameters" in document
      [[Design Notes]](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md)
      for discussion on custom claims vs optional parameters.
    - Sends the evidence format settings and custom claims to the attester
    application.
- Attester application:
    - Generates evidence in the selected format, with the received
    settings and custom claims as well as its own custom claims, with
    `oe_get_evidence()`.
      - Note: the attester can either negotiate with the verifier or decide on
      its own whether to wrap the evidence with an attestation header or not.
      The verifier needs to be informed about the decision, instead of guessing
      by inspecting the evidence data.
    - Sends the evidence to the verifier application.
- Verifier application:
    - Verifies the received evidence, with `oe_verify_evidence()`.

The user experience scenario 2 described in document
[[Attestation V3 Update]](CustomAttestation_V3.md)
can't be supported. As explained in the discussion in
[[Issue #2729]](https://github.com/openenclave/openenclave/issues/2729),
this scenario does not fit the attester – verifier security model as described
in document
[[Design Notes]](https://github.com/openenclave/openenclave/pull/2801).

# OE SDK Attestation Plugin API Proposal

Note: terminologies "evidence format", "plugin", and "plugin library" are used
extensively in this section. For clarification between them please refer to the
[[Design Notes]](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md#evidence-format-plugin-and-plugin-library) document.

## Existing OE SDK V0.9 Plugin API

The OE SDK v0.9 experimental attestation plugin API has two components:
the entry points provided by a plugin for invocation by the OE SDK attestation
framework, and the helper functions provided by the OE SDK framework
(as part of its public API) for
invocation by plugin libraries. For attester and verifier plugins, these two
components are slightly different.

### Existing Attester Plugin API

Below are the use cases for OE SDK framework to interact with an attester plugin.
These use cases are supported by the attester plugin entry points defined in the
`oe_attester_t` structure in header file
[openenclave/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h)
- Execute a function when the plugin is registered.
  - Entry point `oe_result_t (*on_register)(oe_attestation_role_t* context, const void* config_data, size_t config_data_size)`
  - The same entry point definition for both attester and verifier plugins.
- Execute a function when the plugin is unregistered.
  - Entry point `oe_result_t (*on_unregister)(oe_attestation_role_t* context)`
  - The same entry point definition for both attester and verifier plugins.
- Get evidence in a specified format, optionally along with a set of
endorsements.
  - Entry point `oe_result_t (*get_evidence)(oe_attester_t* context, uint32_t flags, const oe_claim_t* custom_claims_buffer, size_t custom_claims_buffer_length, const void* opt_params, size_t opt_params_size, uint8_t** evidence_buffer, size_t* evidence_buffer_size, uint8_t** endorsements_buffer, size_t* endorsements_buffer_size)`.
- Free a dynamically allocated evidence buffer.
  - Entry point `oe_result_t (*free_evidence)(oe_attester_t* context, uint8_t* evidence_buffer)`.
- Free a dynamically allocated endorsements buffer.
  - Entry point `oe_result_t (*free_endorsements)(oe_attester_t* context, uint8_t* endorsements_buffer)`.

In the OE SDK V0.9 release, plugins are managed by application software via the
OE SDK public API.

For SGX, a single attester plugin is implemented for support of the SGX ECDSA
evidence format identified by OE_SGX_PLUGIN_UUID. File
[enclave/sgx/attester.c](https://github.com/openenclave/openenclave/blob/v0.9.x/enclave/sgx/attester.c)
implements all the entry points of this plugin as well as an OE SDK public API
function `oe_sgx_plugin_attester()`.

To setup this plugin, the application software invokes public API function
`oe_sgx_plugin_attester()` to get an `oe_attester_t` structure, and calls public
API function `oe_register_attester()` with this structure.

### Existing Verifier Plugin API

Below are the use cases for the OE SDK framework to interact with a verifier plugin.
These use cases are supported by the verifier plugin entry points defined in the
`oe_verifier_t` structure in header file
[openenclave/plugin.h](https://github.com/openenclave/openenclave/blob/v0.9.x/include/openenclave/attestation/plugin.h)
- Execute a function when the plugin is registered.
  - The same entry point definition as for attester plugins.
- Execute a function when the plugin is unregistered.
  - The same entry point definition as for attester plugins.
- Verify evidence, optionally using a set of input endorsements and policies.
  - Entry point `oe_result_t (*verify_evidence)(oe_verifier_t* context, const uint8_t* evidence_buffer, size_t evidence_buffer_size, const uint8_t* endorsements_buffer, size_t endorsements_buffer_size, const oe_policy_t* policies, size_t policies_size, oe_claim_t** claims, size_t* claims_length)`.
- Free a dynamically allocated claims list buffer.
  - Entry point `oe_result_t (*free_claims_list)(oe_verifier_t* context, oe_claim_t* claims, size_t claims_length)`.

For SGX, a single verifier plugin is implemented for support of the SGX ECDSA
evidence format identified by OE_SGX_PLUGIN_UUID. File
[enclave/sgx/verifier.c](https://github.com/openenclave/openenclave/blob/v0.9.x/enclave/sgx/verifier.c)
implements all the entry points of this plugin as well as an OE SDK public API
function `oe_sgx_plugin_verifier()`.

To setup this plugin, the application software invokes public API function
`oe_sgx_plugin_verifier()` to get an `oe_verifier_t` structure, and calls public
API function `oe_register_verifier()` with this structure.

## Proposed OE SDK V0.1x Plugin API

### Objectives

- Keep plugin design internal between the OE SDK framework and plugin libraries.
  - Initialization of plugin libraries is triggered upon application's OE SDK API
  call to initialize its attester / verifier environment.
  - Upon their initialization, attester / verifier plugin libraries enumerate and
  register their supported plugins.
  - The OE SDK framework provides helper functions for plugin registration. These
  helper functions are not part of the OE SDK public API.
- Remove legacy artifacts that are redundant, e.g. the SGX
local / remote flags.
- Streamline design for support of legacy SGX APIs `oe_get_report()` and
`oe_verify_report()`.

### Proposed Attester Plugin API

Use cases for the OE SDK framework to interact with an attester plugin, supported
by the attester plugin entry points defined in the `oe_attester_t` structure:
- Execute a function when the plugin is registered.
  - The same entry point definition as in the OE SDK V0.9 release.
- Execute a function when the plugin is unregistered:
  - The same entry point definition as in the OE SDK V0.9 release.
- Get evidence in an globally unique format, optionally along with a set of
endorsements.
  - Entry point `oe_result_t (*get_evidence)(oe_attester_t* context, const void* custom_claims_buffer, size_t custom_claims_buffer_size, const void* opt_params, size_t opt_params_size, uint8_t** evidence_buffer, size_t* evidence_buffer_size, uint8_t** endorsements_buffer, size_t* endorsements_buffer_size)`.
  - The legacy `flags` parameter in the OE SDK V0.9 release is removed.
  - The optional custom claims are input as a flat buffer in `custom_claims_buffer`.
  - The output evidence and endorsements data must be held in dynamically
  allocated buffers
  in trusted enclave memory. These buffers will be freed by the plugin framework
  via public functions `oe_free_evidence()` and `oe_free_endorsements()` respectively.
  - Otherwise, this entry point has the same definition as in the OE SDK
  V0.9 release.
- Get a legacy-format report
  - Entry point `oe_result_t (*get_report)(oe_attester_t* context, uint32_t flags, const uint8_t* report_data, size_t report_data_size, const void* opt_params, size_t opt_params_size, uint8_t** report_buffer, size_t* report_buffer_size)`.
  - This entry point must be implemented by a plugin if the OS SDK framework
  needs to support its legacy public API `oe_get_report()` using this plugin.
  - The returned report buffer pointed to by the address in `report_buffer`
  is a contiguous array that can be freed by calling the OE SDK legacy
  public API function `oe_free_report()`.
- Free a dynamically allocated evidence buffer.
  - The same entry point definition as in the OE SDK V0.9 release.
- Free a dynamically allocated endorsements buffer.
  - The same entry point definition as in the OE SDK V0.9 release.

The OE SDK framework exposes a set of helper functions for attester plugin
libraries to interact with it. These helper functions are for plugin library
developers, and not part of the public API for application developers.

Below are the use cases for an attester plugin library to interact with the
OE SDK framework:
- Register an attester plugin.
  - Helper function
  `oe_result_t oe_register_attester_plugin(oe_attester_t* plugin, const void* config_data, size_t config_data_size)`.
  - The same definition as in the OE SDK V0.9 release, except that this function
  is not part of the public API, and the function name is changed.
  - The optional `config_data`, e.g. for holding platform-specific configuration,
  is provided by the plugin library, not by the application as in the V0.9
  release.
- Unregister an attester plugin.
  - Helper function `oe_result_t oe_unregister_attester_plugin(oe_attester_t* plugin)`.
  - The same definition as in the OE SDK V0.9 release, except that this function
  is not part of the public API, and the function name is changed.

In the OE SDK V0.1x release, attester plugins are managed internally between
the OE SDK framework and plugin libraries, without exposing details to
application software. As explained in the
[[Design Notes]](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md#options-for-enclave-side-plugin-library-initialization)
document, when the application calls `oe_attester_initialize()`, this
function invokes the initialization functions of all linked attester plugin
libraries. The initialization function of an attester plugin library enumerates
all evidence formats supported by the library and registers their plugins with
the OE SDK framework via helper function `oe_register_attester()`.

### Proposed Verifier Plugin API

Use cases for the OE SDK framework to interact with a verifier plugin, supported
by the verifier plugin entry points defined in the `oe_verifier_t` structure:
- Execute a function when the plugin is registered.
  - The same entry point definition as for attester plugins.
- Execute a function the plugin is unregistered.
  - The same entry point definition as for attester plugins.
- Get the setting for an evidence format supported by the verifier plugin.
    - Entry point `oe_result_t (*get_format_settings)(oe_verifier_t* context, uint8_t** settings, size_t* settings_size)`.
    - This is a new entry point, not present in the OE SDK V0.9 release.
    - The returned settings is held in a dynamically allocated continuous buffer,
    so the OE SDK framework can free it, and there is no need of a plugin entry
    point.
- Verify evidence, optionally using a set of input endorsements and policies.
  - Entry point `oe_result_t (*verify_evidence)(oe_verifier_t* context, const uint8_t* evidence_buffer, size_t evidence_buffer_size, const uint8_t* endorsements_buffer, size_t endorsements_buffer_size, const oe_policy_t* policies, size_t policies_size, oe_claim_t** claims, size_t* claims_length)`.
  - This entry point has the same definition as in the OE SDK
  V0.9 release.
- Verify a legacy-format report
  - Entry point `oe_result_t (*verify_report)(oe_verifier_t* context, const uint8_t* report, size_t report_size, oe_report_t* parsed_report)`
  - This entry point must be implemented by a plugin if the OS SDK framework needs to
  support the legacy public API `oe_verify_report()` using this plugin.
- Free a dynamically allocated claims buffers.
  - Entry point `oe_result_t (*free_claims)(oe_verifier_t* context, oe_claim_t* claims, size_t claims_length)`.
  - Similar to the `free_claims_list()` entry point definition as in the
  OE SDK V0.9 release, except that the name is changed to be more consistent
  with other attestation API names.

Use cases for a verifier plugin to interact with the OE SDK framework:
- Register a verifier plugin.
  - Helper function
  `oe_result_t oe_register_verifier_plugin(oe_verifier_t* plugin, const void* config_data, size_t config_data_size)`, and the function name is changed.
  - The same definition as in the OE SDK V0.9 release, except that this function
  is not part of the public API.
- Unregister a verifier plugin.
  - Helper function
  `oe_result_t oe_unregister_verifier_plugin(oe_verifier_t* plugin)`.
  - The same definition as in the OE SDK V0.9 release, except that this function
  is not part of the public API, and the function name is changed.

In the OE SDK V0.1x release, initialization of verifier plugin libraries is
triggered with the application call to `oe_verifier_initialize()`.
The initialization function of every linked library enumerates its supported
evidence formats and registers their plugins with the OE SDK framework via
helper function `oe_register_verifier()`.

# Implementation of SGX Plugins

## Existing OE SDK V0.9 Implementation

Only one attester plugin and one verifier plugin are implemented,
for a single SGX ECDSA evidence format identified by `OE_SGX_PLUGIN_UUID`.

The attester plugin entry points are implemented in
[enclave/sgx/attester.c](https://github.com/openenclave/openenclave/blob/v0.9.x/enclave/sgx/attester.c).
The plugin entry points are returned in an `oe_attester_t` structure by the
implementation of the public API function `oe_sgx_plugin_attester()`. This
attester plugin implementation is linked to the OE SDK enclave-side static
library.

The verifier plugin entry points are implemented in
[common/sgx/verifier.c](https://github.com/openenclave/openenclave/blob/v0.9.x/common/sgx/verifier.c).
The plugin entry points are returned in an `oe_verifier_t` structure by the
implementation of the public API function `oe_sgx_plugin_verifier()`. This
verifier plugin implementation is linked to both the OE SDK enclave-side and host-side
static libraries.

## Proposed V0.1x Implementation

The OE SDK V0.1x release will have enclave-side SGX attester plugins for
generation of SGX evidence in local, ECDSA, and EPID formats. These formats
are defined as:
- `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION`: for SGX local attestation.
- `OE_FORMAT_UUID_SGX_ECDSA`: for SGX ECDSA-p256 evidence format
  - Note: this is the same as `OE_SGX_PLUGIN_UUID` in V0.9.
- `OE_FORMAT_UUID_SGX_EPID_LINKABLE`: for SGX linkable EPID evidence format.
- `OE_FORMAT_UUID_SGX_EPID_UNLINKABLE`: for SGX unlinkable EPID evidence format.

These attester plugins will be implemented by a single set of plugin libraries,
composed of:
- One enclave-side SGX evidence generation plugin library.
  - It implements the OE SDK public API function
  `oe_attester_initialize()` for attester plugins enumeration and
  registration, and `oe_attester_shutdown()`.
- One host-side SGX evidence generation plugin library.
  - It implements OCALLs for the enclave-side library to access
  host-side services for SGX quote generation.

The OE SDK V0.1x release will have enclave-side verifier plugins for
verification of `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION` and
`OE_FORMAT_UUID_SGX_ECDSA` evidence,
and host-side verifier plugins for verification of
`OE_FORMAT_UUID_SGX_ECDSA` evidence.
These plugins will be implemented by a single set of
plugin libraries, composed of:
- One enclave-side SGX evidence verification plugin library.
  - It implements the enclave-side OE SDK public API function
  `oe_verifier_initialize()` for enclave-side verifier plugins enumeration
  and registration, and `oe_verifier_shutdown()`.
- One host-side SGX evidence verification plugin library.
  - It implements the host-side OE SDK public API function
  `oe_verifier_initialize()` for host-side verifier plugins enumeration
  and registration, and `oe_verifier_shutdown()`.
  - It also implements OCALLs for the enclave-side library to access
  host-side services for SGX quote verification.

Currently there is no plan to implement verifier plugins for verification of
EPID evidence. Verification of SGX EPID quotes is not supported by
the Intel SGX SDK. In all existing SGX EPID solutions, EPID quotes are sent to
Intel Attestation Service (IAS) backend for verification. For more information,
please see the open-source project
["Intel Software Guard Extensions (SGX) Remote Attestation End-to-End Sample for EPID Attestations"](https://github.com/intel/sgx-ra-sample).
The document ["Code Sample: Intel Software Guard Extensions Remote Attestation End-to-End Example"](https://software.intel.com/content/www/us/en/develop/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example.html)
explains how the EPID-based remote attestation flow implemented in this sample
project works.

The OE SDK V0.1x release will also have enclave-side and host-side plugins
for verification of selected types of OE reports for SGX generated by the legacy
API function `oe_get_report()` and selected types of SGX quotes generated by
the Intel SGX SDK DCAP and quote-ex libraries. Note: the plan is for
the attestation API function `oe_verify_evidence()` to only support a minimum
set of legacy OE reports and SGX quotes as needed. There is no intention for
`oe_verify_evidence()` to support verification of all possible types of legacy
OE reports and SGX quotes.

- `OE_FORMAT_UUID_LEGACY_REPORT_REMOTE`
  - For OE reports generated by the legacy API function `oe_get_report()`
  with the `OE_REPORT_FLAGS_REMOTE_ATTESTATION` flag.
  - Note: no plan to provide verifier plugin for verification of OE reports
  generated by the legacy API function `oe_get_report()` without the
  `OE_REPORT_FLAGS_REMOTE_ATTESTATION` flag (for local attestation).
  These reports can be verified using legacy API function `oe_verify_report()`.
- `OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA`
  - For SGX quotes in ECDSA_P256 format generated by the Intel SGX SDK DCAP
  library, and the Intel SGX quote-ex library with algorithm ID
  `SGX_QL_ALG_ECDSA_P256`.
    - Note: the DCAP library only generates ECDSA-p256 quotes
  - Note: no plan to provide verifier plugin for verification of SGX quotes
  generated by the quote-ex library with other algorithm IDs (e.g. EPID quotes).

For evidence data in format `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION`
or `OE_FORMAT_UUID_SGX_ECDSA`, the custom claims buffer
(if not empty) is attached to the end of the evidence. The list of claims
returned by `oe_verify_evidence()` will contain one claim named
`OE_CLAIM_CUSTOM_CLAIMS_BUFFER` if the evidence data contains a non-empty custom
claims buffer. For evidence data in format `OE_FORMAT_UUID_LEGACY_REPORT_REMOTE`
or `OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA`, since this evidence data embeds the
custom claims buffer in its SGX quote directly,
the list of claims will contain one claim named `OE_CLAIM_SGX_REPORT_DATA`.

For EPID evidence generation, the `custom_claims_buffer` input will be
used as the SGX quote `report_data` directly. This design is consistent with
existing SGX SDK EPID-based solutions behavior, and will help maintain backward
compatibility.

### Summary

The API function `oe_get_evidence()` supports the values listed below in its
`format_id` parameter. The output evidence will be prefixed with an
`oe_attestation_header` if the `OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID` bit in its
`flags` parameter is set.
* `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION`
* `OE_FORMAT_UUID_SGX_ECDSA`
* `OE_FORMAT_UUID_SGX_EPID_LINKABLE`
* `OE_FORMAT_UUID_SGX_EPID_UNLINKABLE`

The API function `oe_verify_evidence()` supports the values listed below in its
`format_id` parameter.
* `NULL`:
  * The input evidence is generated by `oe_get_evidence()`, with
  the `OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID` bit set in its `flags` parameter.
* `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION`:
  * The input evidence is generated by `oe_get_evidence()` for format
  `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION`, with the
  `OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID` bit cleared in its `flags` parameter.
* `OE_FORMAT_UUID_SGX_ECDSA`:
  * The input evidence is generated by `oe_get_evidence()` for format
  `OE_FORMAT_UUID_SGX_ECDSA`, with the
  `OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID` bit cleared in its `flags` parameter.
* `OE_FORMAT_UUID_LEGACY_REPORT_REMOTE`:
  * The input evidence is an OE report generated by the legacy API function
  `oe_get_report()` with the `OE_REPORT_FLAGS_REMOTE_ATTESTATION` flag.
* `OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA`:
  * The input evidence is an SGX ECDSA quote generated by the
  Intel SGX SDK DCAP library, or the quote-ex library with algorithm ID
  `SGX_QL_ALG_ECDSA_P256`.

The table below shows the structure of the evidence data for all the supported
SGX format IDs, as generated by an attester plugin or verified by a verifier
plugin.

| Format ID | Evidence structure  |
| -- | - |
| `OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION` | `[ oe_attestation_header ] \|\| SGX_report(hash) \|\| custom_claims_buffer` |
| `OE_FORMAT_UUID_SGX_ECDSA` | `[ oe_attestation_header ] \|\| SGX_ECDSA_quote(hash) \|\| custom_claims_buffer` |
| `OE_FORMAT_UUID_SGX_EPID_LINKABLE` | `[ oe_attestation_header ] \|\| SGX_EPID_linkable_quote(custom_claims_buffer)` |
| `OE_FORMAT_UUID_SGX_EPID_UNLINKABLE` | `[ oe_attestation_header ] \|\| SGX_EPID_unlinkable_quote(custom_claims_buffer)` |
| `OE_FORMAT_UUID_LEGACY_REPORT_REMOTE` | `oe_report_header (for remote attestation) \|\| SGX_ECDSA_quote(custom_claims_buffer)` |
| `OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA` | `SGX_ECDSA_quote(custom_claims_buffer)` |

In the above table:
* The optional header `oe_attestation_header` is a structure of type
`oe_attestation_header_t`.
* For every format supported by `oe_get_evidence()`, the evidence
will be prefixed with an `oe_attestation_header` when the
`OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID` bit in its `flags` parameter is set.
* `oe_report_header` is the OE report header of type `oe_report_header_t`.
* `hash` is the SHA256 hash of the custom claims held in a flat buffer
`custom_claims_buffer`.
* An SGX report (`SGX_report()`, of type `sgx_report_t`) or quote (`SGX_*quote()`
of type `sgx_quote_t`) embeds a
flat buffer of 64 bytes for its SGX report data field. Depending on the format,
this field holds either the `hash` of the custom claims, or the custom claims
directly.
* Note: for all evidence generated by API `oe_get_evidence()`, the
`oe_report_header` is no longer included.
  * `oe_report_header` was defined for legacy API `oe_get_report()`.
  Its `report_type` field is only intended to only indicate between SGX report
  (for local attestation) and SGX ECDSA-p256 quote (for remote attestation).
  * SGX Verifier plugins are able to identify the `custom_claims_buffer`
  without the help of the `report_size` field in the `oe_report_header`.

### Discussion

The host-side SGX plugin library implementation of the public API functions
`oe_verifier_initialize()` and `oe_verifier_shutdown()` indicates that
this library can't be linked to an verifier application along with
other plugin libraries that implement the same public API functions.
This limitation will be relaxed in a future release when a more sophisticated
mechanism is adopted for plugin library initialization.
More general discussion on evidence formats, plugins, plugin libraries
and their initialization can be found in the "Notes on SGX Plugins Design"
section of the [[Design Notes]](https://github.com/shnwc/openenclave/blob/master/docs/DesignDocs/NotesOnAttestationAPI.md#notes-on-sgx-plugins-design)
document.

Verification of an SGX evidence for local attestation can only be performed by
the enclave to which the SGX report is targeted. So no host-side plugin
for SGX local attestation evidence can be supported.

The OE SDK has legacy API functions `oe_get_report()` and `oe_verify_report()`
for generation and verification of SGX local and ECDSA reports.
If support of these legacy API functions is required, then the plugins for
SGX ECDSA and local evidence formats needs to implement the entry points
`(*get_report)(...)` and `(*verify_report)(...)`, and the OE SDK framework needs
to implement the legacy functions `oe_get_report()` and `oe_verify_report()` on
these entry points respectively.

The Legacy functions `oe_get_report()` and `oe_verify_report()` should be
implemented by the OE SDK framework to first call API functions
`oe_attester_initialize()` and `oe_verifier_initialize()` respectively,
since legacy applications don't call these API functions explicitly.
 As `oe_attester_initialize()` and `oe_verifier_initialize()` are
 idempotent, there is no harm calling them multiple times. For SGX plugins,
 `oe_attester_shutdown()` and `oe_verifier_shutdown()` are NOP, so there
 is no need to call them upon application close.

# Authors

- Shanwei Cen (@shnwc)
