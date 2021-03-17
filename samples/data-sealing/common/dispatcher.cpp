// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/corelibc/stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"

int ecall_dispatcher::seal_data(
    int seal_policy,
    const unsigned char* optional_message,
    size_t optional_message_size,
    const unsigned char* data,
    size_t data_size,
    sealed_data_t** sealed_data,
    size_t* sealed_data_size)
{
    oe_result_t ret;
    uint8_t* blob;
    size_t blob_size;
    sealed_data_t* temp_sealed_data;

    if (optional_message_size > sizeof((*sealed_data)->optional_message))
        return OE_INVALID_PARAMETER;

    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(seal_policy)};
    ret = oe_seal(
        NULL,
        settings,
        sizeof(settings) / sizeof(*settings),
        data,
        data_size,
        optional_message,
        optional_message_size,
        &blob,
        &blob_size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_seal() failed with %d\n", ret);
        goto exit;
    }
    if (blob_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("blob_size is too large to fit into an unsigned int");
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }

    temp_sealed_data =
        (sealed_data_t*)oe_host_malloc(sizeof(*temp_sealed_data) + blob_size);
    if (temp_sealed_data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }

    memset(temp_sealed_data, 0, sizeof(*temp_sealed_data));
    memcpy(
        temp_sealed_data->optional_message,
        optional_message,
        optional_message_size);
    temp_sealed_data->sealed_blob_size = blob_size;
    memcpy(temp_sealed_data + 1, blob, blob_size);

    *sealed_data = temp_sealed_data;
    *sealed_data_size = sizeof(*temp_sealed_data) + blob_size;

exit:
    oe_free(blob);
    return (int)ret;
}

int ecall_dispatcher::unseal_data(
    const sealed_data_t* sealed_data,
    size_t sealed_data_size,
    unsigned char** data,
    size_t* data_size)
{
    uint8_t* temp_data;

    if (sealed_data_size !=
        sealed_data->sealed_blob_size + sizeof(*sealed_data))
    {
        TRACE_ENCLAVE(
            "Seal data does not match the seal data size. Expected %zd, got: "
            "%zd",
            sealed_data->sealed_blob_size + sizeof(*sealed_data),
            sealed_data_size);
        return ERROR_INVALID_PARAMETER;
    }

    int ret = (int)oe_unseal(
        (const uint8_t*)(sealed_data + 1),
        sealed_data->sealed_blob_size,
        sealed_data->optional_message,
        strlen((char*)sealed_data->optional_message),
        &temp_data,
        data_size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_unseal() returns %d\n", ret);
        goto exit;
    }

    *data = (unsigned char*)oe_host_malloc(*data_size);
    if (*data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }

    memcpy(*data, temp_data, *data_size);

exit:
    oe_free(temp_data);
    return ret;
}
