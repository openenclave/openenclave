// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>

#include "enclave.h"

#define HI_U32(x) ((uint32_t)(((x) >> 32) & 0xFFFFFFFF))
#define LO_U32(x) ((uint32_t)((x)&0xFFFFFFFF))

#define PARAM_TYPES_IN_OUT      \
    (TEEC_PARAM_TYPES(          \
        TEEC_VALUE_INPUT,       \
        TEEC_VALUE_INPUT,       \
        TEEC_MEMREF_TEMP_INPUT, \
        TEEC_MEMREF_TEMP_OUTPUT))
#define PARAM_TYPES_IN_NO_OUT   \
    (TEEC_PARAM_TYPES(          \
        TEEC_VALUE_INPUT,       \
        TEEC_VALUE_INPUT,       \
        TEEC_MEMREF_TEMP_INPUT, \
        TEEC_NONE))
#define PARAM_TYPES_NO_IN_OUT \
    (TEEC_PARAM_TYPES(        \
        TEEC_VALUE_INPUT,     \
        TEEC_VALUE_INPUT,     \
        TEEC_NONE,            \
        TEEC_MEMREF_TEMP_OUTPUT))
#define PARAM_TYPES_NO_IN_NO_OUT \
    (TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE))

/* This value is defined in the TEE Client API headers. At the time of this
 * writing, the value is four (4). If the header were to ever change to a lower
 * value, it would cause trouble for all TEE clients. As a result, it's highly
 * unlikely it will ever change. Nevertheless, it doesn't hurt to ensure that
 * the value is indeed at least as large as we assume it to be. */
OE_STATIC_ASSERT(TEEC_CONFIG_PAYLOAD_REF_COUNT >= 4);

static void* _grpc_thread_proc(void* param)
{
    OE_UNUSED(param);
    return NULL;
}

static oe_result_t _uuid_from_string(const char* uuid_str, TEEC_UUID* uuid)
{
    int i;
    uint64_t uuid_parts[5];
    char* id_copy;
    const char* current_token;

    id_copy = strdup(uuid_str);

    /* Remove ".ta" extension, if one is present. */
    size_t len = strlen(id_copy);
    if ((len > 3) && (strcmp(&id_copy[len - 3], ".ta") == 0))
    {
        id_copy[len - 3] = 0;
    }

    if (strlen(id_copy) != 36)
        return OE_INVALID_PARAMETER;

    i = 5;
    current_token = strtok(id_copy, "-");
    while (current_token != NULL && i >= 0)
    {
        uuid_parts[--i] = strtoull(current_token, NULL, 16);
        current_token = strtok(NULL, "-");
    }

    free(id_copy);

    if (i != 0)
        return OE_INVALID_PARAMETER;

    uuid->timeLow = (uint32_t)uuid_parts[4];
    uuid->timeMid = (uint16_t)uuid_parts[3];
    uuid->timeHiAndVersion = (uint16_t)uuid_parts[2];
    uuid->clockSeqAndNode[0] = (uint8_t)(uuid_parts[1] >> (8 * 1));
    uuid->clockSeqAndNode[1] = (uint8_t)(uuid_parts[1] >> (8 * 0));
    uuid->clockSeqAndNode[2] = (uint8_t)(uuid_parts[0] >> (8 * 5));
    uuid->clockSeqAndNode[3] = (uint8_t)(uuid_parts[0] >> (8 * 4));
    uuid->clockSeqAndNode[4] = (uint8_t)(uuid_parts[0] >> (8 * 3));
    uuid->clockSeqAndNode[5] = (uint8_t)(uuid_parts[0] >> (8 * 2));
    uuid->clockSeqAndNode[6] = (uint8_t)(uuid_parts[0] >> (8 * 1));
    uuid->clockSeqAndNode[7] = (uint8_t)(uuid_parts[0] >> (8 * 0));

    return OE_OK;
}

oe_result_t oe_create_enclave(
    const char* enclave_path,
    oe_enclave_type_t enclave_type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    oe_enclave_t** enclave_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave = NULL;

    TEEC_UUID teec_uuid;
    TEEC_Result teec_res;
    uint32_t teec_err_origin;

    bool have_mutex = false;
    bool have_context = false;
    bool have_session = false;

    if (enclave_out)
        *enclave_out = NULL;

    /* Check parameters */
    if (!enclave_path || !enclave_out ||
        ((enclave_type != OE_ENCLAVE_TYPE_OPTEE) &&
         (enclave_type != OE_ENCLAVE_TYPE_AUTO)) ||
        (flags & OE_ENCLAVE_FLAG_RESERVED) ||
        (!(flags & OE_ENCLAVE_FLAG_SIMULATE) &&
         (flags & OE_ENCLAVE_FLAG_DEBUG)) ||
        config || config_size > 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert the path into a TEE UUID. */
    OE_CHECK(_uuid_from_string(enclave_path, &teec_uuid));

    /* Allocate and zero-fill the enclave structure */
    if (!(enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the mutex used to ensure that no two threads ever try to
     * enter an OP-TEE enclave at once.
     */
    if (pthread_mutex_init(&enclave->mutex, NULL))
        OE_RAISE(OE_FAILURE, "pthread_mutex_init failed", NULL);
    have_mutex = true;

    /* Open a context against OP-TEE. */
    if ((teec_res = TEEC_InitializeContext(NULL, &enclave->ctx)) !=
        TEEC_SUCCESS)
        OE_RAISE(
            OE_FAILURE,
            "TEEC_InitializeContext failed with %x",
            teec_res,
            NULL);
    have_context = true;

    /* Open a session against the TA being requested. */
    if ((teec_res = TEEC_OpenSession(
             &enclave->ctx,
             &enclave->session,
             &teec_uuid,
             TEEC_LOGIN_PUBLIC,
             NULL,
             NULL,
             &teec_err_origin)) != TEEC_SUCCESS)
        OE_RAISE(
            OE_FAILURE,
            "TEEC_OpenSession failed with %x and error origin %x",
            teec_res,
            teec_err_origin,
            NULL);
    have_session = true;

    /* Create a thread to process Generic RPCs (OCALLs). */
    if (pthread_create(&enclave->grpc_thread, NULL, _grpc_thread_proc, enclave))
        OE_RAISE(OE_FAILURE, "pthread_create failed", NULL);

    /* Fill out the rest of the enclave structure. */
    enclave->magic = ENCLAVE_MAGIC;
    enclave->uuid = teec_uuid;
    enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
    enclave->num_ocalls = ocall_table_size;

    *enclave_out = enclave;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        if (have_session)
            TEEC_CloseSession(&enclave->session);

        if (have_context)
            TEEC_FinalizeContext(&enclave->ctx);

        if (have_mutex)
            pthread_mutex_destroy(&enclave->mutex);

        if (enclave)
            free(enclave);
    }

    return result;
}

static oe_result_t _oe_invoke_command(
    oe_enclave_t* enclave,
    uint32_t oe_function_id,
    uint64_t table_id,
    uint64_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_FAILURE;

    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Fill in marshalling structure */
    op.params[0].value.a = HI_U32(table_id);
    op.params[0].value.b = LO_U32(table_id);

    op.params[1].value.a = HI_U32(function_id);
    op.params[1].value.b = LO_U32(function_id);

    if (input_buffer)
    {
        op.params[2].tmpref.buffer = (void*)input_buffer;
        op.params[2].tmpref.size = input_buffer_size;
    }

    if (output_buffer)
    {
        op.params[3].tmpref.buffer = (void*)output_buffer;
        op.params[3].tmpref.size = output_buffer_size;
    }

    /* Fill in parameter types */
    if (input_buffer && output_buffer)
        op.paramTypes = PARAM_TYPES_IN_OUT;
    else if (input_buffer)
        op.paramTypes = PARAM_TYPES_IN_NO_OUT;
    else if (output_buffer)
        op.paramTypes = PARAM_TYPES_NO_IN_OUT;
    else
        op.paramTypes = PARAM_TYPES_NO_IN_NO_OUT;

    /* Perform the ECALL */
    res =
        TEEC_InvokeCommand(&enclave->session, oe_function_id, &op, &err_origin);

    /* Check the result */
    if (res != TEEC_SUCCESS)
        OE_RAISE_MSG(
            OE_PLATFORM_ERROR,
            "TEEC_InvokeCommand failed with 0x%x and error origin 0x%x",
            res,
            err_origin);

    /* Done */
    if (output_bytes_written)
        *output_bytes_written = output_buffer_size;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return _oe_invoke_command(
        enclave,
        OE_ECALL_CALL_ENCLAVE_FUNCTION,
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Check parameters */
    if (!enclave || enclave->magic != ENCLAVE_MAGIC)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Clear the magic number */
    enclave->magic = 0;

    /* Close the session with the TA */
    TEEC_CloseSession(&enclave->session);

    /* Finalize the context against OP-TEE */
    TEEC_FinalizeContext(&enclave->ctx);

    /* Destroy the concurrency mutex */
    pthread_mutex_destroy(&enclave->mutex);

    /* Clear the contents of the enclave structure */
    memset(enclave, 0, sizeof(oe_enclave_t));

    /* Free the enclave structure */
    free(enclave);

    result = OE_OK;

done:
    return result;
}
