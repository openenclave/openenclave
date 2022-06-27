# Open Enclave Sealing API

This document describes API functions provided by the Open Enclave SDK for
sealing/unsealing data against an enclave's identity.

Table of Contents:

- [Motivation](#motivation)
  - [Objectives](#objectives)
  - [Non-Objectives](#non-objectives)
- [User Experience](#user-experience)
  - [Specifying Seal Settings](#specifying-seal-settings)
  - [Seal Plug-ins](#seal-plug-ins)
  - [Sealing and Unsealing](#sealing-and-unsealing)
  - [Compatibility with Intel SGX SDK](#compatibility-with-intel-sgx-sdk)
- [Specification](#specification)
  - [New Files](#new-files)
  - [Seal Plug-in APIs](#seal-plug-in-apis)
  - [Sealing APIs](#sealing-apis)
- [Alternatives](#alternatives)
  - [API Definition](#api-definition)
  - [Implementation](#implementation)
  - [Examples](#examples)
- [Authors](#authors)

## Motivation

Sealing is an important capability of TEEs, which allows an enclave to encrypt
and/or integrity-protect data at rest, using keys (aka., sealing keys) derived
from the enclave's own identity. TEEs may have distinct formulas for key
derivation, and may support different key lengths. And that leads to the desire
for a TEE-agnostic sealing API.

### Objectives

The sealing API should be:

- *TEE-agnostic* - The API should hide TEE specifics to allow reuse of source
  code across TEEs.
- *Accommodative* - Should the developers choose to, the API should allow
  explicit uses of TEE specific features. For example, in the case of SGX, the
  API should allow deriving keys of type `PROVISION_SEAL_KEY`, which may not
  have an equivalent on other TEEs.
- *Easy to use* - It's always a challenge for average developers to encrypt
  data securely by using seal keys directly. The API should shield
  cryptographic complexities from developers, by offering comprehensive
  protection through an intuitive interface.
- *Interoperable with existing SDKs* - The Intel SGX SDK also provides sealing
  capabilities. It's desirable for enclaves, regardless of the SDKs they are
  built with, to be able to exchange sealed blobs, when allowed by the policy.

### Non-Objectives

- Cross-device sealing/unsealing is **not** supported - Sealed blobs created on
  a device must be unsealed on that same device.
- Cross-TEE sealing/unsealing is **not** supported - Sealed blobs created by an
  enclave in one TEE (e.g., SGX) cannot be unsealed by another enclave in a
  different TEE (e.g., OP-TEE), even if they were both signed by the same
  private key.

## User Experience

At the minimum, two API functions are necessary, namely `oe_seal()` and
`oe_unseal()`. The former encrypts user data into an opaque blob (whose format
is implementation specific) while the latter decrypts/verifies the given blob
and returns the data back to the user.

### Specifying Seal Settings

Given the diversity in TEEs and also in cryptographic algorithms, a plug-in
model has been adopted. In the model, each plug-in is identified by a *UUID*
(*Universally Unique IDentifier*). The application specifies the plug-in (by
specifying its *GUID*), along with plug-in specific parameters in the form of
an array of `oe_seal_setting_t` structures, detailed in
[Seal Settings](#seal-settings) later in this document.

In practice, the plug-in *UUID* could be `NULL` to select the default plug-in.
The settings array could be `NULL` too to use the default settings provided by
the selected plug-in.

### Seal Plug-ins

At least one seal plug-in must be registered before any sealing/unsealing can
be done. At the time of this document, the OE SDK comes with only one plug-in
for SGX and no plug-in for OP-TEE.

Plug-ins can be registered by invoking `oe_register_seal_plugin()` and
deregistered by `oe_unregister_seal_plugin()`. More details on those two APIs
could be found in [Seal Plug-in APIs](#seal-plug-in-apis).

Plug-ins shall not require explicit registration. Rather, every plug-in shall
be packaged as an object file (.o) and register itself by means of
`__attribute__((constructor))`. The exerpt below from
[seal_gcmaes.c](../../enclave/sealing/sgx/seal_gcmaes.c) shows how to
auto-register a plug-in.

```c
const oe_seal_plugin_definition_t oe_seal_plugin_gcm_aes = {
    { 0xb3, 0x38, 0xde, 0xea, 0x4c, 0x9b, 0x41, 0x88,
      0x90, 0x00, 0x50, 0x5b, 0x8f, 0x63, 0xf7, 0x6f },
    _seal, _unseal
};
__attribute__((constructor)) static void _register_seal_plugin(void)
{
    oe_register_seal_plugin(&oe_seal_plugin_gcm_aes, false);
}
```

Please note that seal plug-ins must be deployed as objects (.o) rather than
archives (.a), otherwise the whole plug-in may be dropped by the linker.

Assuming *CMake* is used, the following statement could be added to an
enclave's `CMakeLists.txt` to link in the desired seal plug-in (i.e.
`openenclave::oeseal_gcmaes` in this example).

```cmake
target_link_libraries(my_enclave_binary
  PRIVATE $<TARGET_OBJECTS:openenclave::oeseal_gcmaes>)
```

Please note that the generator expression `$<TARGET_OBJECTS:...>` (rather than
just the library target) is necessary here to link in the object files
(otherwise, *CMake* would assume archive files by default). A complete example
`CMakeLists.txt` file can be found
[here](../../samples/data-sealing/common/CMakeLists.txt).

### Sealing and Unsealing

Sealing a buffer could be as simple as the the following. Please note that
sealing APIs are defined in `openenclave/seal.h`, which must be included.

```c
#include <openenclave/seal.h>

oe_result_t seal_my_data(
    const uint8_t* data,
    size_t data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    const oe_seal_setting_t seal_settings[] = {
        OE_SEAL_SET_POLICY(OE_SEAL_POLICY_PRODUCT),
    };
    return oe_seal(
        NULL,
        seal_settings,
        sizeof(seal_settings) / sizeof(*seal_settings),
        data,
        data_size,
        NULL,
        0,
        blob,
        blob_size);
}
```

In the example above, the macro `OE_SEAL_SET_POLICY` produces an
`OE_SEAL_SETTING_POLICY` setting that specifies a seal key shared among all
enclaves belonging to the same product. By using such a shared seal key, the
sealed blob could be opened by any enclaves (including a newer self) of the
same product, which on SGX is defined to be the collection of enclaves signed
by the same private key and having the same `PROD_ID`. By default,
`OE_SEAL_POLICY_UNIQUE` would be used to allow only the sealing enclave to
unseal the blob.

Below is a slightly more complicated example to enforce that the unsealer must
have `OE_SGX_FLAGS_PROVISION_KEY` attribute bit set. This is useful on SGX for
provisioning enclaves to seal quote signing keys to be unsealed by quoting
enclaves. Please note that `openenclave/sgx/seal.h` must be included to make
use of SGX specific features.

```c
#include <openenclave/sgx/seal.h>

oe_result_t seal_my_data(
    const uint8_t* data,
    size_t data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    const oe_seal_setting_t seal_settings[] = {
        OE_SEAL_SET_POLICY(OE_SEAL_POLICY_PRODUCT),
        OE_SEAL_SET_SGX_FLAGSMASK(
            OE_SEALKEY_DEFAULT_FLAGSMASK | OE_SGX_FLAGS_PROVISION_KEY),
    };
    return oe_seal(
        NULL,
        seal_settings,
        sizeof(seal_settings) / sizeof(*seal_settings),
        data,
        data_size,
        NULL,
        0,
        blob,
        blob_size);
}
```

Details on `oe_seal()` and `oe_unseal()` could be found in [Sealing
APIs](#sealing-apis) below. Available seal settings are described in [Seal
Settings](#seal-settings). Please refer to
[include/openenclave/seal.h](../../include/openenclave/seal.h) and
[include/openenclave/sgx/seal.h](../../include/openenclave/sgx/seal.h) for
details on `OE_SEAL_SET_*` helper macros.

Unsealing is straight forward.

```c
#include <openenclave/seal.h>

oe_result_t unseal_my_data(
    const uint8_t* blob,
    size_t blob_size,
    uint8_t** data,
    size_t* data_size)
{
    return oe_unseal(blob, blob_size, NULL, 0, data, data_size);
}
```

`oe_seal()` and `oe_unseal()` can optionally authenticate additional data as
well, demonstrated below.

```c
#include <openenclave/seal.h>

oe_result_t seal_my_data(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* aad, // Additional Authenticated Data
    size_t aad_size,
    uint8_t** blob,
    size_t* blob_size)
{
    const oe_seal_setting_t seal_settings[] = {
        OE_SEAL_SET_POLICY(OE_SEAL_POLICY_PRODUCT),
    };
    return oe_seal(
        NULL,
        seal_settings,
        sizeof(seal_settings) / sizeof(*seal_settings),
        data,
        data_size,
        aad,
        aad_size,
        blob,
        blob_size);
}

oe_result_t unseal_my_data(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* aad, // Same AAD is required for verification
    size_t aad_size,
    uint8_t** data,
    size_t* data_size)
{
    return oe_unseal(blob, blob_size, aad, aad_size, data, data_size);
}
```

Please note that the blob produced by `oe_seal()` does *not* contain `aad`,
which must be saved separately and will be needed by `oe_unseal()`.

### Compatibility with Intel SGX SDK

The built-in seal plug-in `openenclave::oeseal_gcmaes` uses the same cipher as
the Intel SGX SDK, and employs a compatible header format. However, they still
differ in

1. OE's blobs don't contain `aad`, while Intel's blobs do.
2. OE's blobs are encrypted with a random *IV*, while Intel's *IV* is always
   <code>0<sup>96</sup></code>.

To produce a sealed blob to be unsealed by the Intel SGX SDK, one must specify
*IV* explicity and concatenate `aad` to the end of the blob.

```c
#include <openenclave/seal.h>

oe_result_t seal_my_data_intel_compatible(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* aad,
    size_t aad_size,
    uint8_t** blob,
    size_t* blob_size)
{
    const uint8_t zero_iv[12] = { 0 };
    const oe_seal_setting_t seal_settings[] = {
        OE_SEAL_SET_POLICY(OE_SEAL_POLICY_PRODUCT),
        OE_SEAL_SET_IV(zero_iv, sizeof(zero_iv)),
    };

    oe_result_t ret = oe_seal(
        NULL,
        seal_settings,
        sizeof(seal_settings) / sizeof(*seal_settings),
        data,
        data_size,
        aad,
        aad_size,
        blob,
        blob_size);

    if (ret == OE_OK) {
        uint8_t* tmp = (uint8_t*)oe_malloc(*blob_size + aad_size);
        if (tmp == NULL)
            ret = OE_OUT_OF_MEMORY;
        else {
            memcpy(tmp, *blob, *blob_size);
            memcpy(tmp + *blob_size, aad, aad_size);
        }

        oe_free(*blob);
        *blob = tmp;
        *blob_size += aad_size;
    }

    return ret;
}
```

To unseal an Intel blob, the size of `aad` must be known.

```c
#include <openenclave/seal.h>

oe_result_t unseal_my_data_intel_compatible()
    const uint8_t* blob,
    size_t blob_size,
    size_t aad_size,
    uint8_t** data,
    size_t* data_size)
{
    blob_size -= aad_size;
    return oe_unseal(
        blob,
        blob_size,
        blob + blob_size,
        aad_size,
        data,
        data_size);
}
```

## Specification

### New Files

- [include/openenclave/seal.h](../../include/openenclave/seal.h)
  defines all APIs along with TEE neutral constants and macros.
- [include/openenclave/sgx/seal.h](../../include/openenclave/sgx/seal.h)
  defines SGX specific constants and macros, and includes
  [include/openenclave/seal.h](../../include/openenclave/seal.h).
- [enclave/sealing/sgx/seal_gcmaes.c](../../enclave/sealing/sgx/seal_gcmaes.c)
  implements an SGX specific seal plug-in based on GCM-AES.

### Seal Plug-in APIs

This section defines `oe_seal_plugin_definition_t`, `oe_register_seal_plugin()`
and `oe_unregister_seal_plugin()`.

#### oe_seal_plugin_definition_t

Each seal plug-in is defined by an `oe_seal_plugin_definition_t` structure.

```c
/**
 * Seal plug-in definition
 */
typedef struct _oe_seal_plugin_definition
{
    /**
     * UUID of the seal plug-in
     */
    const oe_uuid_t id;

    /**
     * Callback function to be called by \c oe_seal() when sealing a blob.
     *
     * @param[in] settings The array of \c oe_seal_setting_t structs passed to
     * \c oe_seal(). If not \c NULL, \c oe_seal() guarantees that the whole \p
     * settings array resides in enclave memory.
     * @param[in] settings_count Number of elements in \p settings.
     * @param[in] plaintext Optional data to be encrypted. If not \c NULL, \c
     * oe_seal() guarantees the whole \p plaintext buffer resides in enclave
     * memory.
     * @param[in] plaintext_size Size of \p plaintext.
     * @param[in] additional_data Optional additional data to be included in
     * authentication (MAC calculation). If not \c NULL, \c oe_seal() guarantees
     * that the whole \p additional_data buffer resides in enclave memory.
     * @param[in] additional_data_size Size of \p additional_data.
     * @param[out] blob Receives the address of the resulted sealed blob. Freed
     * by \c oe_free(). This parameter will never be \c NULL.
     * @param[out] blob_size Receives the size of \p blob on success. This
     * parameter will never be \c NULL.
     *
     * @retval OE_OK The operation succeeded.
     * @retval OE_INVALID_PARAMETER At least one seal setting was invalid.
     * @retval OE_UNSUPPORTED Unrecognized seal settings.
     * @retval OE_OUT_OF_MEMORY Memory allocation failed.
     */
    oe_result_t (*seal)(
        const oe_seal_setting_t* settings,
        size_t settings_count,
        const uint8_t* plaintext,
        size_t plaintext_size,
        const uint8_t* additional_data,
        size_t additional_data_size,
        uint8_t** blob,
        size_t* blob_size);

    /**
     * Callback function to be called by \c oe_unseal() when unsealing a blob.
     *
     * @param[in] blob The blob to be unsealed. \c oe_unseal() doesn't validate
     * this parameter.
     * @param[in] blob_size Size of \p blob. \c oe_unseal() doesn't validate
     * this parameter.
     * @param[in] additional_data Optional additional data for verification.
     * This must match \p additional_data passed to \c oe_seal(). If not \c
     * NULL, \c oe_unseal() guarantees that the whole \p additional_data buffer
     * resides in enclave memory.
     * @param[in] additional_data_size Size of \p additional_data.
     * @param[out] plaintext Receives the pointer to the decrypted data on
     * success. Freed by \c oe_free().  This parameter will never be \c NULL.
     * @param[out] plaintext_size Receives the size of \p plaintext on success.
     * This parameter will never be \c NULL.
     *
     * @retval OE_OK Unsealed \p blob successfully.
     * @retval * All other values are considered failure and will cause \c
     * oe_unseal() to try the next plug-in.
     */
    oe_result_t (*unseal)(
        const uint8_t* blob,
        size_t blob_size,
        const uint8_t* additional_data,
        size_t additional_data_size,
        uint8_t** plaintext,
        size_t* plaintext_size);
} oe_seal_plugin_definition_t;
```

In `oe_seal_plugin_definition_t`,

- `id` is the *UUID* of the plug-in, and is usually generated randomly by the
  plug-in developer.
- `seal` is called by `oe_seal()` to perform the actual encryption and output
  the opaque sealed blob.
  - The sealed blob must contain all necessary information to allow derivation
    of the same seal key for unsealing by `unseal` of the same plug-in.
  - `oe_seal()` doesn't, hence it is the plug-in's responsibility to, validate
    the contents of `settings`.
  - See [oe_seal()](#oe_seal) below for more details.
- `unseal` is called by `oe_unseal()` to perform the actual decryption of
  `blob` and verification of the optional `additional_data`.
  - On success, `OE_OK` shall be returned to inform `oe_unseal()` to exit back
    to its caller.
  - On failure, an error code (i.e., any error code other than `OE_OK`) shall
    be returned to let `oe_unseal()` move to the next plug-in.
  - See [oe_unseal()](#oe_unseal) below for more details.

#### oe_register_seal_plugin()

Plug-ins are registered by calling `oe_register_seal_plugin()` API. A plug-in
must be registered before use. Please see comments inside the code snippet
below for more details.

```c
/**
 * Register a plug-in to be used by oe_seal() and oe_unseal().
 *
 * @param[in] plugin Pointer to the plug-in being registered
 * @param[in] make_default \c TRUE to make this plug-in the default plug-in. A
 * registered plug-in could be made default by registering it again with \p
 * make_default set to \c TRUE, but a default plug-in cannot be made
 * non-default by setting \p make_default to \c FALSE.
 *
 * @retval OE_OK \p plugin was registered successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Too many plug-ins have been registered.
 */
oe_result_t oe_register_seal_plugin(
    const oe_seal_plugin_definition_t* plugin,
    bool make_default);
```

Most plug-ins auto-register themselves, hence this API is rarely needed/used by
enclave developers.

#### oe_unregister_seal_plugin()

Plug-ins could be deregistered by calling `oe_unregister_seal_plugin()` API.
Please note that deregistration of plug-ins are rarely required. Please see
comments inside the code snippet below for more details.

```c
/**
 * Unregister a plug-in identified by its UUID.
 *
 * @param[in] plugin_id Pointer to the UUID of the plug-in being unregistered.
 *
 * @retval OE_OK plug-in was unregistered successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
oe_result_t oe_unregister_seal_plugin(const oe_uuid_t* plugin_id);
```

#### Example

Please refer to
[enclave/sealing/sgx/seal_gcmaes.c](../../enclave/sealing/sgx/seal_gcmaes.c)
for an exmaple on how to write a seal plug-in.

### Sealing APIs

This section specifies seal settings, and gives definitions of `oe_seal()` and
`oe_unseal()`.

#### Seal Settings

Seal settings are passed to `oe_seal()` as TLV (Type, Length, Value) tuples,
using the `oe_seal_setting_t` structure as defined below.

```c
/**
 * Seal settings as TLV tuples.
 *
 * It's strongly recommended to use OE_SEAL_SET_* helper macros to set up this
 * structure, rather than assigning to members directly.
 */
typedef struct _oe_seal_setting
{
    int type;      ///< Setting type. See oe_seal_setting_type_t for details.
    uint32_t size; ///< Size of the buffer pointed to by \c value.p
    union {
        uint64_t q; ///< quad-word value. \c size should be set to \c 0.
        uint32_t d; ///< double-word value. \c size should be set to \c 0.
        uint16_t w; ///< word value. \c size should be set to \c 0.
        uint8_t b;  ///< byte value. \c size should be set to \c 0.
        const void*
            p; ///< buffer. \c size should be set to the buffer size in bytes.
    } value;
} oe_seal_setting_t;
```

Where,

- `type` is the setting type. More details follow.
- `size` is the size of the buffer pointed to by `value.p`, otherwise `0`.
- `value` is an union. Which of its members is valid depends on `type`.

  **Note**: For each `OE_SEAL_SETTING_*`, there's a helper macro
  `OE_SEAL_SET_*` for setting up the whole tuple (`type`, `size` and the
  corresponding union member of `value`) in one shot. Direct assignments to
  union members are strongly discouraged. Sample code could be found in
  [here](../../samples/data-sealing/common/dispatcher.cpp).

Currently, defined TEE neutral settings are summarized in the table blow. These
constants are all defined in
[include/openenclave/seal.h](../../include/openenclave/seal.h), along with
corresponding helper macros.

|Seal Setting                        |Type      |Description
|------------------------------------|----------|-----------
|`OE_SEAL_SETTING_POLICY`            |`uint16_t`|Either `OE_SEAL_POLICY_UNIQUE` (default) or `OE_SEAL_POLICY_PRODUCT`.
|`OE_SEAL_SETTING_ADDITIONAL_CONTEXT`|*Buffer*  |Buffer pointed to by `value.p` of size `size` will be mixed into the seal key. Please note that not every plug-in supports this setting. It's recommended *not* to specify this setting unless absolutely necessary.
|`OE_SEAL_SETTING_IV`                |*Buffer*  |Buffer pointed to by `value.p` of size `size` will be used as *IV* (*Initialization Vector*) by the underlying cipher/mode. Please note that not every cipher/mode uses IV. And the plug-in may require *IV* of specific sizes. It's recommended *not* to specify this setting unless absolutely necessary.

SGX specific seal settings are summarized in the table below. These constants
are all defined in
[include/openenclave/sgx/seal.h](../../include/openenclave/sgx/seal.h), along
with corresponding helper macros.

|Seal Setting                             |Type      |Description
|-----------------------------------------|----------|-----------
|`OE_SEAL_SETTING_SGX_KEYNAME`            |`uint16_t`|Value of `value.w` will be assigned to `KEYREQUEST.KEYNAME`.
|`OE_SEAL_SETTING_SGX_ISVSVN`             |`uint16_t`|Value of `value.w` will be assigned to `KEYREQUEST.ISVSVN`.
|`OE_SEAL_SETTING_SGX_CET_ATTRIBUTES_MASK`|`uint8_t` |Value of `value.b` will be assigned to `KEYREQUEST.CET_ATTRIBUTES_MASK`. Please note that OpenEnclave SDK does **not** support *CET* at the time this document is written.
|`OE_SEAL_SETTING_SGX_CPUSVN`             |*Buffer*  |Buffer pointed to by `value.p` will be copied to `KEYREQUEST.CPUSVN`. `size` must be `sizeof(KEYREQUEST.CPUSVN)`.
|`OE_SEAL_SETTING_SGX_FLAGSMASK`          |`uint64_t`|Value of `value.q` will be assigned to `KEYREQUEST.FLAGSMASK`.
|`OE_SEAL_SETTING_SGX_XFRMMASK`           |`uint64_t`|Value of `value.q` will be assigned to `KEYREQUEST.XFRMMASK`.
|`OE_SEAL_SETTING_SGX_MISCMASK`           |`uint32_t`|Value of `value.d` will be assigned to `KEYREQUEST.MISCMASK`.
|`OE_SEAL_SETTING_SGX_CONFIGSVN`          |`uint16_t`|Value of `value.w` will be assigned to `KEYREQUEST.CONFIGSVN`.

#### oe_seal()

`oe_seal()` encrypts user-supplied data into an opaque blob, using a key
derived from the calling enclave's identity.

Please see comments inside the code snippet below for details on the function
parameters.

```c
/**
 * Seal data to an enclave using AEAD (Authenticated Encryption with
 * Additioonal Data).
 *
 * @param[in] plugin_id Optional UUID of the plugin to use. If \c NULL, the
 * default plugin will be used.
 * @param[in] settings Optional array of seal settings to be used.
 * @param[in] settings_count The number of settings specified by \p settings.
 * Must be \c 0 if \p settings is \c NULL.
 * @param[in] plaintext Optional buffer to be encrypted under the seal key.
 * @param[in] plaintext_size Size of \p plaintext, must be \c 0 if \p plaintext
 * is \c NULL.
 * @param[in] additional_data Optional additional data to be authenticated
 * under the seal key. This is usually referred to as AAD (Additional
 * Authenticated Data) in cryptographic literatures.
 * @param[in] additional_data_size Size of \p additional_data, must be \c 0 if
 * \p additional_data is \c NULL.
 * seal key.
 * @param[out] blob On success, receives the pointer to a buffer containing
 * encrypted \p plaintext, along with necessary information for unsealing.
 * Freed by \c oe_free().
 * @param[out] blob_size On success, receives the size of \p blob.
 *
 * @retval OE_OK \p plaintext was sealed to the enclave successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_UNSUPPORTED One or more unsupported seal settings are specified.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_CRYPTO_ERROR An error occurred during encryption.
 */
oe_result_t oe_seal(
    const oe_uuid_t* plugin_id,
    const oe_seal_setting_t* settings,
    size_t settings_count,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size);
```

Internally, `oe_seal()` does the following:

1. Look up the plug-in using `plugin_id`.
   - If `plugin_id` is `NULL`, the default plug-in will be selected.
   - Return `OE_NOT_FOUND` if no plug-in is found.
2. Validate `settings` and `settings_count`, and return `OE_INVALID_PARAMETER`
   if either of the following fails.
   - Verify that `(settings == NULL) == (settings_count == 0)`.
   - Verify that the whole `settings` array resides in enclave memory.
3. Validate `plaintext` and `plaintext_size` in the same way as above.
4. Validate `additional_data` and `additional_data_size` in the same way as
   above.
5. For each `setting[i]`,
   - Verify that `setting[i].type` is in the range of
     `[0, OE_SEAL_SETTING_MAX)`.
   - If `setting[i].size > 0` (i.e., a buffer is associated with this setting),
     verify that the buffer pointed to by `setting[i].value.p` of size
     `setting[i].size` resides in enclave memory.
6. Verify that neither `blob` nor `blob_size` is `NULL`, or return
   `OE_INVALID_PARAMETER`.
7. Call the plug-in's `seal()` method and pass through all the parameters
   except `plugin_id`, and pass the return value back to the caller.

#### oe_unseal()

`oe_unseal()` decrypts a sealed blob created by `oe_seal()`.

Please see comments inside the code snippet below for details on the function
parameters.

```c
/**
 * Unseal a blob sealed by \c oe_seal().
 *
 * @param[in] blob The blob to be unsealed.
 * @param[in] blob_size Size of \p blob.
 * @param[in] additional_data Optional additional data for verification. This
 * must match \p additional_data passed to \c oe_seal().
 * @param[in] additional_data_size Size of \p additional_data.
 * @param[out] plaintext Optional parameter to receive the pointer to the
 * decrypted data on success. Freed by \c oe_free().
 * @param[out] plaintext_size Optional parameter to receive the size of \p
 * plaintext on success. This parameter must be \c NULL if \p plaintext is \c
 * NULL.
 *
 * @retval OE_OK Unsealed \p blob successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_UNSUPPORTED Error occurred during decryption, due to either
 * tampered blob or missing plug-in.
 */
oe_result_t oe_unseal(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** plaintext,
    size_t* plaintext_size);
```

Internally, `oe_unseal()` does the following:

1. Validate `additional_data` and `additional_data_size`, and return
   `OE_INVALID_PARAMETER` if either of the following fails.
   - Verify that `(additional_data == NULL) == (additional_data_size == 0)`.
   - Verify that the whole `additional_data` buffer resides in enclave memory.
2. For each registered plug-in, pass through all parameters to its `unseal`
   method.
   - Return `OE_OK` to the caller if `unseal` succeeded.
   - Otherwise, try the next registered plug-in.
3. If none of the registered plug-ins return `OE_OK`, return `OE_UNSUPPORTED`
   to its caller.

## Alternatives

This section describes an alternative design that doesn't make use of plug-ins.

### API Definition

`oe_seal()` and `oe_unseal()` are defined below.

```c
oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size);

oe_result_t oe_unseal(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** plaintext,
    size_t* plaintext_size);
```

`oe_seal()` in this alternative design differs with the current
[oe_seal()](#oe_seal) in

- No plug-in is involved. This alternative expects `oe_seal()` to be
  implemented in a TEE-specific manner.
- Parameters for seal key derivation are passed in the TEE specific
  `oe_seal_key_info_t`, rather than TLV tuples.
  - To allow TEE agnostic (source) code, a helper API -
    `oe_initialize_seal_key_info()` has been introduced, whose definition is
    given below.
  - `oe_seal_key_info_t` is TEE specific (i.e., it is a `typedef` of
    `sgx_key_request_t` on SGX) but *not* implementation specific - i.e.,
    unlike TLV tuples via which plug-in specific parameters could be passed,
    `oe_seal_key_info_t` does *not* convey any implementation specific
    parameters.

`oe_unseal()` in this alternative has an identical signature to the current
[oe_unseal](#oe_unseal). However, its implementation is expected to unseal the
blob by itself, rather than passing it through to plug-ins.

The definition of the helper API `oe_initialize_seal_key_info()` is given below

```c
oe_result_t oe_initialize_seal_key_info(
    oe_seal_key_info_t* key_info,
    oe_seal_policy_t seal_policy,
    const uint8_t* entropy,
    size_t entropy_size);
```

Where,

- `key_info` points to the `oe_seal_key_info_t` instance being initialized.
- `seal_policy` is equivalent to `OE_SEAL_SETTING_POLICY` seal setting in the
  current design.
- `entropy` and `entropy_size` specify a buffer for additional context data to
  be mixed into the seal key. This is equivalent to
  `OE_SEAL_SETTING_ADDITIONAL_CONTEXT`.

### Implementation

With `oe_get_seal_key()` encapsulating TEE specifics, the source code of
`oe_seal()` and `oe_unseal()` can be TEE agnostic. Below is a possible
implementation. Please note that `ki_entropy` referenced in the source below
should be defined to the member of `key_info` that contains entropy - e.g.,
`#define ki_entropy key_id` on SGX.

```c
oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    uint8_t* key = NULL;
    size_t key_size = 0;

    oe_sealed_blob_header_t* header;
    oe_entropy_kind_t k;
    uint8_t* payload;
    size_t size;
    oe_result_t result = OE_OK;

    OE_STATIC_ASSERT(sizeof(*key_info) == sizeof(header->key_info));

    if (key_info == NULL || blob == NULL || blob_size == NULL)
        return OE_INVALID_PARAMETER;

    size = sizeof(*header);
    if (size > OE_UINT32_MAX - plaintext_size)
        return OE_INVALID_PARAMETER;
    size += plaintext_size;

    header = (oe_sealed_blob_header_t*)oe_calloc(1, size);
    if (header == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    oe_secure_zero_fill(header, sizeof(*header));

    OE_CHECK(oe_memcpy_s(
        &header->key_info, sizeof(header->key_info), key_info, sizeof(key_info)));

    OE_CHECK(oe_get_entropy(
        header->key_info.ki_entropy, sizeof(header->key_info.ki_entropy), &k));

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->key_info, sizeof(header->key_info), &key, &key_size));

    payload = (uint8_t*)(header + 1);
    OE_STATIC_ASSERT(sizeof(header->tag) >= 16);
    OE_CHECK(oe_aes_gcm_encrypt(
        key,
        key_size,
        header->iv,
        sizeof(header->iv),
        additional_data,
        additional_data_size,
        plaintext,
        plaintext_size,
        payload,
        header->tag));

    header->ciphertext_size = (uint32_t)plaintext_size;
    header->payload_size = (uint32_t)(plaintext_size + additional_data_size);

    *blob = (uint8_t*)header;
    *blob_size = size;

done:
    oe_free_seal_key(key, NULL);
    if (result != OE_OK)
        oe_free(header);
    return result;
}

oe_result_t oe_unseal(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** plaintext,
    size_t* plaintext_size)
{
    oe_sealed_blob_header_t* header;
    uint8_t* payload;
    uint8_t* key = NULL;
    size_t key_size = 0;
    oe_result_t result = OE_OK;

    if (blob == NULL || blob_size < sizeof(*header) ||
        (additional_data == NULL) != (additional_data_size == 0))
        return OE_INVALID_PARAMETER;

    header = (oe_sealed_blob_header_t*)blob;
    payload = (uint8_t*)(header + 1);
    if (header->ciphertext_size != blob_size - sizeof(*header) ||
        header->payload_size != header->ciphertext_size + additional_data_size)
        return OE_UNEXPECTED;

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->key_info,
        sizeof(header->key_info),
        &key,
        &key_size));

    OE_CHECK(oe_aes_gcm_decrypt(
        key,
        key_size,
        header->iv,
        sizeof(header->iv),
        additional_data,
        additional_data_size,
        payload,
        header->ciphertext_size,
        header->tag));

    if (plaintext)
        *plaintext = payload;
    if (plaintext_size)
        *plaintext_size = header->ciphertext_size;

done:
    oe_free_seal_key(key, NULL);
    return result;
}
```

Crypto-agility is provided by offering multiple implementations for users to
choose.

`oe_initialize_seal_key_info()` should supply reasonable default values for the
whole `oe_seal_key_info_t` structure. and should be shared across all
implementations (on the same TEE) for  consistent user experience.

Each implementation then provides its own `oe_seal()` and `oe_unseal()` in its
own library, so that users could switch between sealing implementations easily
(by placing the desired implementation library on the linker's command line).

`oe_seal()` and `oe_unseal()` can pass `key_info` through to
`oe_get_seal_key()` for deriving the seal key. In this way, (source code of)
implementations could be TEE agnostic.

In some rare cases, multiple implementations need to coexist. Here is an
example to show how to allow multiple sealing implementations to coexist in the
same enclave.

Below is the pseudocode for an implementation based on algorithm *algo1*.
Please note that `oe_seal()` is defined as a weak refernce to
`oe_seal_algo1()`.

```c
oe_result_t oe_seal_algo1(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size)
{
    // Implemented using algo1 ...
}

oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size) __attribute__((weak, alias("oe_seal_algo1")));
```

Similarly, a different implementation based on algorithm *algo2* could look
like the following.

```c
oe_result_t oe_seal_algo2(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size)
{
    // Implemented using algo2 ...
}

oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size) __attribute__((weak, alias("oe_seal_algo2")));
```

Then in the most common cases where only one implementation is linked,
`oe_seal()` could be used to reference either implementation (depending on
which one is linked); while in the rare case of both implementations
being linked, `oe_seal_algo1()` and `oe_seal_algo2()` could be used to
reference specific implementations.

### Examples

In the most common cases (where just a "general" sealing capability is needed),
one could take the output of `oe_initialize_seal_key_info()` as is, shown in
the code snippet below.

```c
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    oe_result_t result;
    oe_seal_key_info_t key_info;

    result = oe_initialize_seal_key_info(
        &key_info,
        OE_SEAL_POLICY_PRODUCT,
        NULL,
        0);

    if (result == OE_OK)
        result = oe_seal(
            &key_info,
            my_data,
            my_data_size,
            NULL,
            0,
            blob,
            blob_size);

    return result;
}
```

In the rare cases where TEE-specific parameters are necessary for seal key
derivation, one could assign to members of `key_info` directly after calling
`oe_initialize_seal_key_info()`. Below is an example to seal a blob that can be
unsealed only by an (SGX) enclave with provisioning key access. This technique
is typically used by SGX *Provisioning Enclaves* (aka. PvE) to pass secrets
(quote signing keys) to *Quoting Enclaves* (aka. *QE*).

```c
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    oe_result_t result;

    result = oe_initialize_seal_key_info(
        &key_info,
        OE_SEAL_POLICY_PRODUCT,
        NULL,
        0);

    if (result == OE_OK)
    {
        key_info.attribute_mask.flags =
            OE_SEALKEY_DEFAULT_FLAGSMASK | OE_SGX_FLAGS_PROVISION_KEY;
        // More assignments to key_info.*, if need, can go here...

        result = oe_seal(
            &key_info,
            my_data,
            my_data_size,
            NULL,
            0
            blob,
            blob_size);
    }
    return result;
}
```

## Authors

Cedric Xing (cedric.xing@intel.com)
