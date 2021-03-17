// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include <openenclave/seal.h>

#define _OE_MAX_SEAL_PLUGIN 16

static oe_mutex_t _plugins_lock = OE_MUTEX_INITIALIZER;

static const oe_seal_plugin_definition_t* _plugins[_OE_MAX_SEAL_PLUGIN];
static int _num_plugins = 0;

oe_result_t oe_register_seal_plugin(
    const oe_seal_plugin_definition_t* plugin,
    bool make_default)
{
    oe_result_t result = OE_OK;
    int i, index;

    if (plugin == NULL)
        return OE_INVALID_PARAMETER;

    if (oe_mutex_lock(&_plugins_lock) != OE_OK)
        return OE_UNEXPECTED;

    if (_num_plugins >= _OE_MAX_SEAL_PLUGIN)
        OE_RAISE(OE_OUT_OF_MEMORY);

    index = -1;
    for (i = 0; i < _num_plugins && index < 0; ++i)
        if (memcmp(&_plugins[i]->id, &plugin->id, sizeof(plugin->id)) == 0)
            index = i;
    if (index < 0)
        index = _num_plugins++;

    if (make_default && index > 0)
    {
        _plugins[index] = _plugins[0];
        index = 0;
    }

    _plugins[index] = plugin;

done:
    oe_mutex_unlock(&_plugins_lock);
    return result;
}

oe_result_t oe_unregister_seal_plugin(const oe_uuid_t* plugin_id)
{
    oe_result_t result;
    int i;

    if (plugin_id == NULL)
        return OE_INVALID_PARAMETER;

    if (oe_mutex_lock(&_plugins_lock) != OE_OK)
        return OE_UNEXPECTED;

    result = OE_NOT_FOUND;
    for (i = 0; result != OE_OK && i < _num_plugins; ++i)
        if (memcmp(&_plugins[i]->id, plugin_id, sizeof(*plugin_id)) == 0)
        {
            _plugins[i] = _plugins[--_num_plugins];
            result = OE_OK;
        }

    oe_mutex_unlock(&_plugins_lock);
    return result;
}

static const oe_seal_plugin_definition_t* _find_plugin(
    const oe_uuid_t* plugin_id)
{
    int i;

    if (plugin_id == NULL && _num_plugins > 0)
        return _plugins[0];

    for (i = 0; i < _num_plugins; ++i)
        if (memcmp(&_plugins[i]->id, plugin_id, sizeof(*plugin_id)))
            return _plugins[i];
    return NULL;
}

oe_result_t oe_seal(
    const oe_uuid_t* plugin_id,
    const oe_seal_setting_t* settings,
    size_t settings_count,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    oe_result_t result;
    const oe_seal_plugin_definition_t* plugin;
    size_t i;

    if (blob == NULL || blob_size == NULL)
        return OE_INVALID_PARAMETER;

    *blob = NULL;
    *blob_size = 0;

    if ((settings == NULL) != (settings_count == 0) ||
        !oe_is_within_enclave(settings, settings_count * sizeof(*settings)) ||
        (plaintext == NULL) != (plaintext_size == 0) ||
        !oe_is_within_enclave(plaintext, plaintext_size) ||
        (additional_data == NULL) != (additional_data_size == 0) ||
        !oe_is_within_enclave(additional_data, additional_data_size))
        return OE_INVALID_PARAMETER;

    for (i = 0; i < settings_count; ++i)
    {
        if (settings[i].type < 0 || settings[i].type >= OE_SEAL_SETTING_MAX)
            return OE_INVALID_PARAMETER;
        if (settings[i].size > 0 &&
            !oe_is_within_enclave(settings[i].value.p, settings[i].size))
            return OE_INVALID_PARAMETER;
    }

    if (oe_mutex_lock(&_plugins_lock) != OE_OK)
        return OE_UNEXPECTED;

    plugin = _find_plugin(plugin_id);
    if (plugin == NULL)
        OE_RAISE(OE_NOT_FOUND);

    result = plugin->seal(
        settings,
        settings_count,
        plaintext,
        plaintext_size,
        additional_data,
        additional_data_size,
        blob,
        blob_size);

done:
    oe_mutex_unlock(&_plugins_lock);
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
    oe_result_t result;
    uint8_t* decrypted = NULL;
    size_t decrypted_size;
    int i;

    if (blob == NULL || blob_size == 0 ||
        (additional_data == NULL) != (additional_data_size == 0) ||
        !oe_is_within_enclave(additional_data, additional_data_size))
        return OE_INVALID_PARAMETER;

    if (plaintext == NULL)
        plaintext = &decrypted;
    if (plaintext_size == NULL)
        plaintext_size = &decrypted_size;

    *plaintext = NULL;
    *plaintext_size = 0;

    if (oe_mutex_lock(&_plugins_lock) != OE_OK)
        return OE_UNEXPECTED;

    for (i = 0; i < _num_plugins; ++i)
    {
        result = _plugins[i]->unseal(
            blob,
            blob_size,
            additional_data,
            additional_data_size,
            plaintext,
            plaintext_size);
        if (result == OE_OK)
            goto done;
    }

    result = OE_UNSUPPORTED;

done:
    oe_mutex_unlock(&_plugins_lock);

    if (decrypted != NULL)
    {
        oe_secure_zero_fill(decrypted, *plaintext_size);
        oe_free(decrypted);
    }

    return result;
}
