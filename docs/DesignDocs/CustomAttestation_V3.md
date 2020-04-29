Custom Attestation Data Formats for Open Enclave V3 Updates
================

As custom attestation plugins are developed and features are requested, new APIs were added to:

1. Query built-in attester and verifier plugins to be registered.
2. Select a format of the evidence that the registered attesters can generate.
3. Query verifier settings to be used as optional inputs when generating evidences.

The following API was affected:

1. Built-in attester and verifier plugins

This document describes the added and affected APIs as well as keeping the existing support for version 2 of the API. This document assumes the user is familiar with the Open Enclave attestation and [custom attestation](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/CustomAttestation.md) with plugins.

Motivation
----------

New APIs were added to help customers who would like to extend Open Enclave's current attestation structure with extra information while keeping TEE-specific information within attester and verifier plugins.

1. The application can query built-in attester and verifier plugins to be registered. This allows the plugin library to return attesters and verifiers based on configuration.

```C
   //// Attester application
   // Old
   oe_register_attester(oe_attesterX(), NULL, 0);
   oe_register_attester(oe_attesterY(), NULL, 0);
   oe_register_attester(oe_attesterZ(), NULL, 0);

   // New
   oe_get_attester_plugins(&attesters, &attesters_length);
   for (n = 0; n < attesters_length; n++)
      oe_register_attester(&attesters[n], NULL, 0);

   //// Verifier application
   // Old
   oe_register_verifier(oe_verifierY(), NULL, 0);
   oe_register_verifier(oe_verifierZ(), NULL, 0);

   // New
   oe_get_verifier_plugins(&verifiers, &verifiers_length);
   for (n = 0; n < verifiers_length; n++)
      oe_register_verifier(&verifiers[n], NULL, 0);
```

2. The attester application can rely on the SDK to select a matching evidence format.

```C
   // Old
   const oe_uuid_t attester_formats[3] = {{ATTESTERX_UUID}, {ATTESTERY_UUID}, {ATTESTERZ_UUID}};
   selected_format = NULL;
   for (n = 0; n < requested_formats_length && !selected_format; n++)
   {
       for (m = 0; m < countof(attester_formats) && !selected_format; m++)
       {
           if (requested_formats[n] == attester_formats[m])
               selected_format = &attester_formats[m];
       }
   }

   // New
   oe_select_attester_format(
       requested_formats,
       requested_formats_length,
       &selected_format);
```

3. The application gets verifier settings from verifiers. Some evidence generation needs information from verifier. For example, local report generation takes 'target info' from verifier so the evidence is targeted only to the requested verifier. Other protocols may be defined a 'nonce' to be sent from verifier to the attester to be included in the evidence.

```C
   // Old
   uint8_t opt_paramsX[] = { OPT_PARAMS_X };
   uint8_t opt_paramsY[] = { OPT_PARAMS_Y };
   if (format == ATTESTERX_UUID)
   {
      oe_get_evidence(&format, 0, NULL, 0, opt_paramsX, sizeof(opt_paramsX), &evidence, &evidence_size, NULL, NULL);
   }
   else if (format == ATTESTERY_UUID)
   {
       oe_get_evidence(&format, 0, NULL, 0, opt_paramsY, sizeof(opt_paramsY), &evidence, &evidence_size, NULL, NULL);
   }

   // New
   uint8_t* verifier_settings;
   size_t verifier_settings_size;
   oe_get_verifier_settings(&format, &verifier_settings, &verifier_settings_size);

   oe_get_evidence(&format, 0, NULL, 0, verifier_settings, verifier_settings_size, &evidence, &evidence_size, NULL, NULL);
```

4. Open Enclave local and remote attestation generations take different inputs and generate data of different structures. The local/remote attestation concept is TEE specific. To prevent confusion at evidence generation, local and remote attestation each has its own format and the OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION and OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION flags were deprecated.

```C
   // Old
   oe_get_evidence(&format_local_and_remote, OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION, NULL, 0, opt_params, opt_params_size, &evidence, &evidence_size, NULL, NULL);
   oe_get_evidence(&format_local_and_remote, OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION, NULL, 0, NULL, 0, &evidence, &evidence_size, NULL, NULL);
   oe_get_evidence(&format_local_only, OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION, NULL, 0, NULL, 0, &evidence, &evidence_size, NULL, NULL); // Error
   oe_get_evidence(&format_remote_only, OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION, NULL, 0, NULL, 0, &evidence, &evidence_size, NULL, NULL); // Error

   // New
   oe_get_evidence(&format_X, 0, NULL, 0, opt_params, opt_params_size, &evidence, &evidence_size, NULL, NULL);
   oe_get_evidence(&format_Y, 0, NULL, 0, opt_params, opt_params_size, &evidence, &evidence_size, NULL, NULL);
```

User Experience
---------------
The user experience is improved by the changes. Many attestation protocols can be defined using the attestation APIs. These are a couple of examples:

Scenario 1 - Attester selects from a list of evidence formats that can be verified:
- Verifier application
    1. Upon initialization, queries available verifiers to the application (oe_get_verifier_plugins) and registers them (oe_register_verifier).
    2. Builds the format IDs of the registered verifiers sorted by preference.
    3. Sends the format IDs to the attester application.
- Attester application
    1. Upon initialization, queries available attesters to the application (oe_get_attester_plugins) and registers them (oe_register_attester).
    2. Receives format IDs from the verifier application.
    3. Selects a format ID from the received format IDs (oe_select_attester_format).
    4. Sends the format ID to the verifier application.
- Verifier application
    1. Gets verifier settings for the received format ID (oe_get_verifier_settings). The format of the verifier settings is a contract defined by the verifier and the attester of the format. It could be a 'nonce' to avoid replay attacks or a 'target info' to target the evidence recipient. This is an optional step.
    2. Sends the verifier settings to the attester application.
- Attester application
    1. Generates an evidence (oe_get_evidence) of the selected format optionally with the received verifier settings.
    2. Sends the evidence to the verifier application.
- Verifier application
    1. Verifies the received evidence (oe_verify_evidence).

Scenario 2 - Attester sends evidences of different formats until the verifier can verify:
- Attester application
    1. Upon initialization, queries available attesters to the application (oe_get_attester_plugins) and registers them (oe_register_attester).
    2. Picks a preferred evidence format it can generate without additional inputs and generates the evidence (oe_get_evidence) of that format.
    3. Sends the evidence to the verifier application along with a list of alternative format IDs it supports.
- Verifier application
    1. Upon initialization, queries available verifiers to the application (oe_get_verifier_plugins) and registers them (oe_register_verifier).
    2. Verifies the received evidence (oe_verify_evidence). If the verification succeeds, we are done.
    3. If the verification fails, selects an evidence format from the attester's supported list, based on the verifier's preference. Sends the selected evidence format along with the verifier's settings (oe_get_verifier_settings) to the attester application.
- Attester application
    1. Generates an evidence (oe_get_evidence) of the received format and sends it to the verifier application.

Specification
-------------

## Differences between V2 and V3 APIs.

Most of the APIs to attestation plugins are the same between the versions. The differences are highlighted below.

## Changes

### New APIs to query and select attester and verifier plugins

```C
/**
 * oe_get_attester_plugins
 *
 * Helper function that returns the built-in attester plugins that can then be sent to
 * `oe_register_attester`.
 *
 * @experimental
 * @param[out] attesters The attesters that are available to the application.
 * @param[out] attesters_length The length of the attesters.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_attester_plugins(oe_attester_t** attesters, size_t *attesters_length);

/**
 * oe_free_attester_plugins
 *
 * Frees the attester plugins.
 *
 * @experimental
 * @param[in] attesters The attesters to be freed.
 * @retval OE_OK on success.
 */
oe_result_t oe_free_attester_plugins(oe_attester_t* attesters);

/**
 * oe_get_verifier_plugins
 *
 * Helper function that returns the built-in verifier plugins that can then be sent to
 * `oe_register_verifier`.
 *
 * @experimental
 * @param[out] verifiers The verifiers that are available to the application.
 * @param[out] verifiers_length The length of the verifiers.
 * @retval OE_OK on success.
 */
oe_result_t oe_get_verifier_plugins(oe_verifier_t** verifiers, size_t *verifiers_length);

/**
 * oe_free_verifier_plugins
 *
 * Frees the verifier plugins.
 *
 * @experimental
 * @param[in] verifiers The list of the verifiers.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_free_verifier_plugins(oe_verifier_t* verifiers);

/**
 * oe_select_attester_format
 *
 * From the list, select an evidence format that the registered attesters
 * can generate. If there's more than one match, the first one in the list
 * wins.
 *
 * @experimental
 * @param[in] format_ids The list of the format ids.
 * @param[in] format_ids_length The length of the format ids list.
 * @param[out] selected_format_id The selected id from the evidence
 * format ids list.
 * @retval OE_OK on success.
 * @retval OE_NOT_FOUND if none of the format ids match any registered attesters.
 * @retval other appropriate error code.
 */
oe_result_t oe_select_attester_format(
    const oe_uuid_t* format_ids,
    size_t format_ids_length,
    oe_uuid_t** selected_format_id);

/**
 * oe_get_verifier_settings
 *
 * Get verifier settings from the verifier of the specified format id.
 * These settings are to be used by attester as optional inputs when generating evidence.
 * The format of the verifier settings is a contract defined by the verifier and
 * the attester of the format. For example, it could be a 'nonce' to avoid replay attacks or
 * a 'target info' to target the evidence recipient.
 *
 * @experimental
 * @param[in] format_id The format id of the verifier to get verifier settings from.
 * @param[out] settings The verifier settings.
 * @param[out] settings_size The size of the verifier settings.
 * @retval OE_OK on success.
 * @retval OE_NOT_FOUND if none of the format ids match any registered verifier.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_verifier_settings(
    const oe_uuid_t* format_id,
    uint8_t** settings,
    size_t* settings_size);

/**
 * oe_free_verifier_settings
 *
 * Frees the verifier settings.
 *
 * @experimental
 * @param[in] settings The verifier settings.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval other appropriate error code.
 */
 oe_result_t oe_free_verifier_settings(uint8_t* settings);
```
### Deprecate built-in SGX plugin and local/remote flags
```C
#if (OE_API_VERSION < 3)
/**
 * Helper function that returns the SGX attester that can then be sent to
 * `oe_register_attester`.
 *
 * @deprecated This function is deprecated. Use oe_get_attester_plugins instead.
 *
 * @retval A pointer to the SGX attester. This function never fails.
 */
oe_attester_t* oe_sgx_plugin_attester(void);

/**
 * Helper function that returns the SGX verifier that can then be sent to
 * `oe_register_verifier`.
 *
 * @deprecated This function is deprecated. Use oe_get_verifier_plugins instead.
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_verifier(void);

/**
 * Flags passed to oe_get_evidence() function.
 *
 * @deprecated These flags are deprecated. Specify attester format
 * IDs that are specifically for local or remote attestations instead.
 *
 */
#define OE_EVIDENCE_FLAGS_LOCAL_ATTESTATION 0x00000000
#define OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION 0x00000001
#endif
```
### New verifier callback function

```C
/**
 * The verifier attestation role. The verifier is responsible for verifying the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_verifier oe_verifier_t;
struct _oe_verifier
{
    ...

    /**
     * get_settings
     *
     * Get verifier settings that are to be used by attester as optional
     * inputs when generating evidence.
     *
     * @experimental
     * @param[out] settings The verifier settings.
     * @param[out] settings_size The size of the verifier settings.
     * @retval OE_OK on success.
     * @retval other appropriate error code.
     */
    oe_result_t (*get_settings(
        uint8_t** settings,
        size_t* settings_size);
};
```

## Code samples
More plugin code snippets are available in [CustomAttestation.md](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/CustomAttestation.md). The sample below is mainly for demonstrating the use of new APIs.

The plugin-aware verifier application, which can either be the enclave or the host, can verify the evidence like this:

`verifier.c`

```C
#include <verifier.h>

/* Register verifiers upon initialization. */
oe_verifier_t* verifiers;
size_t verifiers_length;
oe_get_verifier_plugins(&verifiers, &verifiers_length);
for (size_t n = 0; n < verifiers_length; n++)
    oe_register_verifier(&verifiers[n], NULL, 0);

/* Build array of registered verifier format IDs. */
_build_format_ids(verifiers, verifiers_length, &format_ids);

/* Send the format IDs that can be verified to the attester.
   Protocol is up to enclave and verifier. */
send(VERIFIER_SOCKET_FD, format_ids, verifiers_length*sizeof(oe_uuid_t), 0);

/* Receive a selected format ID. */
recv(ENCLAVE_SOCKET_FD, &format_id, &format_id_size, 0);

/* Get verifier settings for the format ID. */
oe_get_verifier_settings(format_id, &settings, &settings_size);

/* Send the verifier settings to the attester */
send(VERIFIER_SOCKET_FD, settings, settings_size, 0);

/* Receive evidence and endorsement buffer from enclave. */
recv(ENCLAVE_SOCKET_FD, evidence, evidence_size, 0);
recv(ENCLAVE_SOCKET_FD, endorsements, endorsements_size, 0);

/* Verify evidence. Can check the claims if desired. */
oe_verify_evidence(
    evidence,
    evidence_size,
    endorsements,
    endorsements_size,
    NULL,
    0,
    &claims,
    &claims_size);

/* Free data and unregister plugin. */
oe_free_verifier_settings(settings);
oe_free_format_ids(format_ids);
oe_free_claims_list(claims, claims_size);
for (size_t n = 0; n < verifiers_length; n++)
    oe_unregister_verifier(&verifiers[n]);
oe_free_verifier_plugins(verifiers);
```

The plugin-aware application enclave can generate the evidence using the plugin like this:

`attester.c`

```C
#include <attester.h>

/* Register attesters upon initialization. */
oe_attester_t* attesters;
size_t attesters_length;
oe_get_attester_plugins(&attesters, &attesters_length);
for (size_t n = 0; n < attesters_length; n++)
    oe_register_attester(&attester[n], NULL, 0);

/* Receive format IDs from verifier. Protocol is up to enclave and verifier. */
recv(ENCLAVE_SOCKET_FD, &format_ids, &format_ids_size, 0);

/* Selects a format ID from the received format IDs. */
oe_select_attester_format(format_ids, format_ids_size/sizeof(oe_uuid_t), &selected_format);

/* Send the selected format to verifier */
send(ENCLAVE_SOCKET_FD, selected_format, sizeof(oe_uuid_t), 0);

/* Receive verifier settings. */
recv(ENCLAVE_SOCKET_FD, &verifier_settings, &verifier_settings_size, 0);

/* Get evidence. */
oe_get_evidence(
    selected_format,
    0,
    NULL,
    0,
    verifier_settings,
    verifier_settings_size,
    &evidence,
    &evidence_size,
    &endorsements,
    &endorsements_size);

/* Send the evidence to the verifier. */
send(VERIFIER_SOCKET_FD, evidence, evidence_size, 0);
send(VERIFIER_SOCKET_FD, endorsements, endorsements_size, 0);

/* Free data and unregister plugin. */
oe_free_format_ids(selected_format);
oe_free_format_ids(format_ids);
oe_free_evidence(evidence);
oe_free_endorsements(endorsements);
oe_free_verifier_settings(verifier_settings);
for (size_t n = 0; n < attesters_length; n++)
    oe_unregister_attester(&attesters[n]);
oe_free_attester_plugins(attesters);
```

Authors
-------

Name: Yen Lee

email: yenlee@microsoft.com

github username: yentsanglee
