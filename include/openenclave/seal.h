// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file
 *
 * This file defines constants and structures for sealing APIs.
 *
 * Only TEE agnostic definitions should go in this file. SGX specific
 * definitions should go in sgx/seal.h
 *
 */
#ifndef _OE_SEAL_H
#define _OE_SEAL_H

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

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
    union
    {
        uint64_t q; ///< quad-word value. \c size should be set to \c 0.
        uint32_t d; ///< double-word value. \c size should be set to \c 0.
        uint16_t w; ///< word value. \c size should be set to \c 0.
        uint8_t b;  ///< byte value. \c size should be set to \c 0.
        const void*
            p; ///< buffer. \c size should be set to the buffer size in bytes.
    } value;
} oe_seal_setting_t;

/*
 * TEE agnostic seal settings supported by OE SDK
 */
enum oe_seal_setting_type_t
{
    /**
     * Desired sealing policy - either \c OE_SEAL_POLICY_UNIQUE or \c
     * OE_SEAL_POLICY_PRODUCT.
     */
    OE_SEAL_SETTING_POLICY,

    /**
     * Additional context to be included in seal key derivation. Please note
     * that not every seal plug-in supports this setting, in which case
     * \coe_seal() will return \c OE_UNSUPPORTED. It's highly recommended NOT
     * to specify this setting.
     */
    OE_SEAL_SETTING_ADDITIONAL_CONTEXT,

    /**
     * IV (Initialization Vector) to use should the underlying cipher require
     * one. It's highly recommended NOT to specify this setting.
     */
    OE_SEAL_SETTING_IV,

    /**
     * Upper bound of seal setting types.
     *
     * No seal setting types shall be defined at or above this.
     */
    OE_SEAL_SETTING_MAX = 0x10000,

    /**
     * Lower bound of plug-in defined setting types.
     *
     * All values below this are reserved by OpenEnclave SDK.
     */
    OE_SEAL_SETTING_PLUGIN_DEFINED = OE_SEAL_SETTING_MAX / 2
};

#define __OE_SEAL_SET_POINTER(t, p, s) \
    {                                  \
        (t), s,                        \
        {                              \
            (uint64_t)(p)              \
        }                              \
    }
#define __OE_SEAL_SET_VALUE(t, v) __OE_SEAL_SET_POINTER(t, v, 0)

/**
 * Initialize a \c oe_seal_setting_t structure to specify seal policy.
 *
 * @param[in] w Should be either \c OE_SEAL_POLICY_UNIQUE or \c
 * OE_SEAL_POLICY_PRODUCT.
 */
#define OE_SEAL_SET_POLICY(w) __OE_SEAL_SET_VALUE(OE_SEAL_SETTING_POLICY, w)

/**
 * Initialize a \c oe_seal_setting_t structure to specify additional context
 * for seal key derivation.
 *
 * It is recommended **not** to specify this setting to allow the plug-in to
 * use a random context. Please note that not every plug-in supports this
 * setting.
 *
 * @param[in] p Points to a buffer containing the additional context.
 * @param[in] s Size of \p p.
 */
#define OE_SEAL_SET_CONTEXT(p, s) \
    __OE_SEAL_SET_POINTER(OE_SEAL_SETTING_ADDITIONAL_CONTEXT, p, s)

/**
 * Initialize a \c oe_seal_setting_t structure to specify IV (Initialization
 * Vector) used by the underlying cipher.
 *
 * It is recommended **not** to specify this setting to allow the plug-in to
 * use a random IV. Please note that not every plug-in supports this setting.
 *
 * @param[in] p Points to a buffer containing the IV.
 * @param[in] s Size of \p p. Please note that the underlying cipher may require
 * a specific size, in which case sizes other than required will cause \c
 * oe_seal() to return \c OE_INVALID_PARAMETER.
 */
#define OE_SEAL_SET_IV(p, s) __OE_SEAL_SET_POINTER(OE_SEAL_SETTING_IV, p, s)

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
 * Authenticated Data) in cryptographic literature.
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

/**
 * Register a plug-in to be used by oe_seal() and oe_unseal().
 *
 * @param[in] plugin Pointer to the plug-in being registered.
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

/**
 * Unregister a plug-in identified by its UUID.
 *
 * @param[in] plugin_id Pointer to the UUID of the plug-in being unregistered.
 *
 * @retval OE_OK plug-in was unregistered successfully.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
oe_result_t oe_unregister_seal_plugin(const oe_uuid_t* plugin_id);

OE_EXTERNC_END

#endif /* _OE_SEAL_H */
