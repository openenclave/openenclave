// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>

#include "enclave.h"

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

oe_result_t oe_ecall(
    oe_enclave_t* enclave,
    uint16_t func,
    uint64_t arg,
    uint64_t* arg_out_ptr)
{
    oe_result_t result = OE_UNEXPECTED;
    // oe_code_t code = OE_CODE_ECALL;
    oe_code_t code_out = 0;
    // uint16_t func_out = 0;
    uint16_t result_out = 0;
    uint64_t arg_out = 0;

    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Perform ECALL or ORET */
    OE_UNUSED(func);
    OE_UNUSED(arg);

    /* Process OCALLS */
    if (code_out != OE_CODE_ERET)
        OE_RAISE(OE_UNEXPECTED);

    if (arg_out_ptr)
        *arg_out_ptr = arg_out;

    result = (oe_result_t)result_out;

done:

    return result;
}

oe_result_t oe_call_enclave_function_by_table_id(
    oe_enclave_t* enclave,
    uint64_t table_id,
    uint64_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_enclave_function_args_t args;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the call_enclave_args structure */
    {
        args.table_id = table_id;
        args.function_id = function_id;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t arg_out = 0;

        OE_CHECK(oe_ecall(
            enclave,
            OE_ECALL_CALL_ENCLAVE_FUNCTION,
            (uint64_t)&args,
            &arg_out));
        OE_CHECK((oe_result_t)arg_out);
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
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
    return oe_call_enclave_function_by_table_id(
        enclave,
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
    OE_UNUSED(enclave);
    return OE_UNSUPPORTED;
}
