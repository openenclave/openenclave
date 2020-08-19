// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>

#include "../../calls.h"
#include "../../ocalls/ocalls.h"
#include "enclave.h"

// clang-format off

/**
 * TEE Parameter Types used when invoking functions inside the TA.
 *
 * Each invocation includes four TEEC_Parameter structures, used for the
 * following purposes, by index, then by component:
 *
 * 0: Platform-specific data
 *    Unused.
 *
 * 1: Open Enclave-specific data
 *    Tmpref: Arguments marshaling structure, if any.
 *        Note: This parameter is not used for built-in ECALLs.
 *
 * 2: Input parameter
 *    Tmpref: The input parameters buffer, if any.
 *
 * 3: Output parameter
 *    Tmpref: The output parameters buffer, if any.
 *
 * A similar pattern is used when the enclave calls into the host via an OCALL.
 * There is no reason why the pattern is similar, other than for consistency.
 *
 * See enclave/core/optee/gp.c.
 */

#define PT_BUILTIN_CALL_IN_OUT          \
    (TEEC_PARAM_TYPES(                  \
        TEEC_NONE,                      \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_INPUT,         \
        TEEC_MEMREF_TEMP_OUTPUT))

#define PT_ENCLAVE_CALL_IN_OUT          \
    (TEEC_PARAM_TYPES(                  \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_INOUT,         \
        TEEC_MEMREF_TEMP_INPUT,         \
        TEEC_MEMREF_TEMP_OUTPUT))
#define PT_ENCLAVE_CALL_IN_NO_OUT       \
    (TEEC_PARAM_TYPES(                  \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_INOUT,         \
        TEEC_MEMREF_TEMP_INPUT,         \
        TEEC_NONE))
#define PT_ENCLAVE_CALL_NO_IN_OUT       \
    (TEEC_PARAM_TYPES(                  \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_INOUT,         \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_OUTPUT))
#define PT_ENCLAVE_CALL_NO_IN_NO_OUT    \
    (TEEC_PARAM_TYPES(                  \
        TEEC_NONE,                      \
        TEEC_MEMREF_TEMP_INOUT,         \
        TEEC_NONE,                      \
        TEEC_NONE))

// clang-format on

/* This value is defined in the TEE Client API headers. At the time of this
 * writing, the value is four (4). If the header were to ever change to a lower
 * value, it would cause trouble for all TEE clients. As a result, it's highly
 * unlikely it will ever change. Nevertheless, it doesn't hurt to ensure that
 * the value is indeed at least as large as we assume it to be. */
OE_STATIC_ASSERT(TEEC_CONFIG_PAYLOAD_REF_COUNT >= 4);

static oe_result_t _handle_call_host_function(
    void* inout_buffer,
    size_t inout_buffer_size,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    oe_call_host_function_args_t* args_ptr;

    oe_ocall_func_t func;
    ocall_table_t ocall_table;

    size_t buffer_size;

    /* Check parameters */
    if (!inout_buffer ||
        inout_buffer_size != sizeof(oe_call_host_function_args_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The in/out buffer contains the OCALL parameters structure */
    args_ptr = (oe_call_host_function_args_t*)inout_buffer;
    if (args_ptr == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    ocall_table.ocalls = enclave->ocalls;
    ocall_table.num_ocalls = enclave->num_ocalls;

    /* Fetch matching function */
    if (args_ptr->function_id >= ocall_table.num_ocalls)
        OE_RAISE(OE_NOT_FOUND);

    func = ocall_table.ocalls[args_ptr->function_id];
    if (func == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    /* TODO: Is due to limits imposed by the ECALL/ERET mechanism and therefore
     * SGX-specific?
     */
    OE_CHECK(
        oe_safe_add_u64(input_buffer_size, output_buffer_size, &buffer_size));

    /* Buffer sizes must be pointer aligned */
    if ((input_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((output_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Call the function */
    func(
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        &args_ptr->output_bytes_written);

    /* The ocall succeeded */
    args_ptr->result = OE_OK;
    result = OE_OK;

done:
    return result;
}

static TEEC_Result _handle_generic_rpc(
    int func,
    void* inout_buffer,
    size_t inout_buffer_size,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    void* context)
{
    oe_enclave_t* enclave = (oe_enclave_t*)context;

    switch ((oe_func_t)func)
    {
        case OE_OCALL_CALL_HOST_FUNCTION:
            _handle_call_host_function(
                inout_buffer,
                inout_buffer_size,
                input_buffer,
                input_buffer_size,
                output_buffer,
                output_buffer_size,
                enclave);
            break;

        case OE_OCALL_MALLOC:
            HandleMalloc(*(uint64_t*)input_buffer, (uint64_t*)output_buffer);
            break;

        case OE_OCALL_FREE:
            HandleFree(*(uint64_t*)input_buffer);
            break;

        case OE_OCALL_THREAD_WAIT:
            return TEEC_ERROR_NOT_SUPPORTED;

        case OE_OCALL_THREAD_WAKE:
            return TEEC_ERROR_NOT_SUPPORTED;

        case OE_OCALL_GET_TIME:
            oe_handle_get_time(
                *(uint64_t*)input_buffer, (uint64_t*)output_buffer);
            break;

        default:
        {
            /* No function found with the number */
            return TEEC_ERROR_ITEM_NOT_FOUND;
        }
    }

    return TEEC_SUCCESS;
}

static void* _grpc_thread_proc(void* param)
{
    TEEC_Result res;
    oe_enclave_t* enclave = (oe_enclave_t*)param;

    /* This function only returns when the TA is terminated */
    res = TEEC_ReceiveReplyGenericRpc(
        &enclave->session, _handle_generic_rpc, enclave);

    return (void*)(uintptr_t)res;
}

static oe_result_t _handle_call_builtin_function(
    oe_enclave_t* enclave,
    uint16_t func,
    uint64_t arg_in,
    uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;

    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    /* Host OS-specific data (only used on Windows) */
    memset(&op.params[0], 0, sizeof(op.params[0]));

    /* Unused */
    memset(&op.params[1], 0, sizeof(op.params[1]));

    /* Input buffer */
    op.params[2].tmpref.buffer = &arg_in;
    op.params[2].tmpref.size = sizeof(arg_in);

    /* Output buffer */
    op.params[3].tmpref.buffer = (void*)arg_out;
    op.params[3].tmpref.size = sizeof(*arg_out);

    /* Fill in parameter types */
    op.paramTypes = PT_BUILTIN_CALL_IN_OUT;

    /* Perform the ECALL */
    res = TEEC_InvokeCommand(&enclave->session, func, &op, &err_origin);

    /* Check the result */
    if (res != TEEC_SUCCESS)
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "TEEC_InvokeCommand failed with 0x%x and error origin 0x%x",
            res,
            err_origin);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _handle_call_enclave_function(
    oe_enclave_t* enclave,
    oe_call_enclave_function_args_t* args)
{
    oe_result_t result = OE_UNEXPECTED;

    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    /* Host OS-specific data (only used on Windows) */
    memset(&op.params[0], 0, sizeof(op.params[0]));

    /* Open Enclave-specific data */
    op.params[1].tmpref.buffer = args;
    op.params[1].tmpref.size = sizeof(*args);

    /* Input buffer */
    if (args->input_buffer)
    {
        op.params[2].tmpref.buffer = (void*)args->input_buffer;
        op.params[2].tmpref.size = args->input_buffer_size;
    }

    /* Output buffer */
    if (args->output_buffer)
    {
        op.params[3].tmpref.buffer = (void*)args->output_buffer;
        op.params[3].tmpref.size = args->output_buffer_size;
    }

    /* Fill in parameter types */
    if (args->input_buffer && args->output_buffer)
        op.paramTypes = PT_ENCLAVE_CALL_IN_OUT;
    else if (args->input_buffer)
        op.paramTypes = PT_ENCLAVE_CALL_IN_NO_OUT;
    else if (args->output_buffer)
        op.paramTypes = PT_ENCLAVE_CALL_NO_IN_OUT;
    else
        op.paramTypes = PT_ENCLAVE_CALL_NO_IN_NO_OUT;

    /* Perform the ECALL */
    res = TEEC_InvokeCommand(
        &enclave->session, OE_ECALL_CALL_ENCLAVE_FUNCTION, &op, &err_origin);

    /* Check the result */
    if (res != TEEC_SUCCESS)
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "TEEC_InvokeCommand failed with 0x%x and error origin 0x%x",
            res,
            err_origin);

    /* Extract the result */
    result = *(oe_result_t*)args->output_buffer;

done:
    return result;
}

static oe_result_t _uuid_from_string(const char* uuid_str, TEEC_UUID* uuid)
{
    int i;
    uint64_t uuid_parts[5];
    char* id_copy;
    const char* current_token;

    id_copy = strdup(uuid_str);

    /* Remove ".ta" extension, if one is present */
    size_t len = strlen(id_copy);
    if ((len > 3) && (strcmp(&id_copy[len - 3], ".ta") == 0))
    {
        id_copy[len - 3] = 0;
    }

    if (strlen(id_copy) != 36)
        return OE_FAILURE;

    i = 5;
    current_token = strtok(id_copy, "-");
    while (current_token != NULL && i >= 0)
    {
        uuid_parts[--i] = strtoull(current_token, NULL, 16);
        current_token = strtok(NULL, "-");
    }

    free(id_copy);

    if (i != 0)
        return OE_FAILURE;

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
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_count,
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
        (setting_count > 0 && settings == NULL) ||
        (setting_count == 0 && settings != NULL) ||
        (flags & OE_ENCLAVE_FLAG_RESERVED) ||
        (!(flags & OE_ENCLAVE_FLAG_SIMULATE) &&
         (flags & OE_ENCLAVE_FLAG_DEBUG)))
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
    enclave->path = strndup(
        enclave_path, 38); // 37 + 1 = length of a UUID + NULL terminator
    enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
    enclave->num_ocalls = ocall_count;

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
    uint64_t arg_in,
    uint64_t* arg_out)
{
    oe_result_t result;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Dispatch ECALL based on function */
    if (func == OE_ECALL_CALL_ENCLAVE_FUNCTION)
    {
        result = _handle_call_enclave_function(
            enclave, (oe_call_enclave_function_args_t*)arg_in);
    }
    else
    {
        result = _handle_call_builtin_function(enclave, func, arg_in, arg_out);
    }

done:
    return result;
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
