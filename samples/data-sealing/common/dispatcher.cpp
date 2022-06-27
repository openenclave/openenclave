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
    data_t* sealed_data)
{
    oe_result_t ret;
    uint8_t* blob;
    size_t blob_size;
    sealed_data_t* temp_sealed_data;

    if (optional_message_size > sizeof(temp_sealed_data->optional_message))
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
        (sealed_data_t*)malloc(sizeof(*temp_sealed_data) + blob_size);
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

    sealed_data->data = (uint8_t*)temp_sealed_data;
    sealed_data->size = sizeof(*temp_sealed_data) + blob_size;

exit:
    oe_free(blob);
    return (int)ret;
}

int ecall_dispatcher::unseal_data(
    const data_t* sealed_data,
    const int optional_msg_flag,
    data_t* output_data)
{
    sealed_data_t* unwrapped_sealed_data;
    size_t temp_data_size;
    uint8_t* temp_data;

    unwrapped_sealed_data = (sealed_data_t*)sealed_data->data;

    if (sealed_data->size != unwrapped_sealed_data->sealed_blob_size +
                                 sizeof(*unwrapped_sealed_data))
    {
        TRACE_ENCLAVE(
            "Seal data does not match the seal data size. Expected %zd, got: "
            "%zd",
            unwrapped_sealed_data->sealed_blob_size +
                sizeof(*unwrapped_sealed_data),
            sealed_data->size);
        return ERROR_INVALID_PARAMETER;
    }

    int ret = (int)oe_unseal(
        (const uint8_t*)(unwrapped_sealed_data + 1),
        unwrapped_sealed_data->sealed_blob_size,
        (optional_msg_flag == 1) ? unwrapped_sealed_data->optional_message
                                 : NULL,
        (optional_msg_flag == 1)
            ? strlen((char*)unwrapped_sealed_data->optional_message)
            : 0,
        &temp_data,
        &temp_data_size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_unseal() returns %d\n", ret);
        goto exit;
    }

    output_data->data = temp_data;
    output_data->size = temp_data_size;

exit:
    return ret;
}
