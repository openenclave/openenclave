/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

#include "sal_unsup.h"
#include "tcps_u.h"
#include <sgx_edger8r.h>
#include <openenclave/host.h>
#include "TcpsCalls_u.h"
#include "optee.h"
#include "oeresult.h"

static TEEC_Result handle_generic_rpc(
    int type,
    void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size,
    void *context)
{
    sgx_status_t sgxStatus;
    struct tcps_optee_context *optee;

    optee = (struct tcps_optee_context *)context;

    if (type < V2_FUNCTION_ID_OFFSET) {
        if (type >= optee->ocall_table->nr_ocall)
            return TEEC_ERROR_BAD_PARAMETERS;

        if (input_buffer_size > output_buffer_size)
            return TEEC_ERROR_BAD_PARAMETERS;

        memcpy(output_buffer, input_buffer, input_buffer_size);
        
        sgxStatus = optee->ocall_table->func_addr[type](output_buffer);
    } else {
        if (type >= g_ocall_table_v2.nr_ocall)
            return TEEC_ERROR_BAD_PARAMETERS;

        uint32_t bytes_written = 0;
        type = type - V2_FUNCTION_ID_OFFSET;
        g_ocall_table_v2.call_addr[type](
            input_buffer,
            input_buffer_size,
            output_buffer,
            output_buffer_size,
            &bytes_written);
        
        sgxStatus = SGX_SUCCESS;
    }

    return sgxStatus == SGX_SUCCESS ? TEEC_SUCCESS : TEEC_ERROR_GENERIC;
}

static void *generic_rpc_thread_procedure(void *param)
{
    TEEC_Result res;

    struct tcps_optee_context *optee;

    optee = (struct tcps_optee_context *)param;
    res = TEEC_ReceiveReplyGenericRpc(&optee->session, handle_generic_rpc, optee);

    return (void *)(uintptr_t)res;
}

static Tcps_StatusCode uuid_from_string(
    char *a_TaIdString,
    TEEC_UUID *a_Uuid)
{
    int i;
    uint64_t uuid_parts[5];
    char *id_copy;
    const char *current_token;

    if (strlen(a_TaIdString) != 36)
        return Tcps_BadInvalidArgument;

    id_copy = strdup(a_TaIdString);

    i = 5;
    current_token = strtok((char *)id_copy, "-");
    while (current_token != NULL && i >= 0) {
        uuid_parts[--i] = strtoull(current_token, NULL, 16);
        current_token = strtok(NULL, "-");
    }

    free(id_copy);

    if (i != 0)
        return Tcps_BadInvalidArgument;

    a_Uuid->timeLow            = (uint32_t)uuid_parts[4];
    a_Uuid->timeMid            = (uint16_t)uuid_parts[3];
    a_Uuid->timeHiAndVersion   = (uint16_t)uuid_parts[2];
    a_Uuid->clockSeqAndNode[0] = (uint8_t)(uuid_parts[1] >> (8 * 1));
    a_Uuid->clockSeqAndNode[1] = (uint8_t)(uuid_parts[1] >> (8 * 0));
    a_Uuid->clockSeqAndNode[2] = (uint8_t)(uuid_parts[0] >> (8 * 5));
    a_Uuid->clockSeqAndNode[3] = (uint8_t)(uuid_parts[0] >> (8 * 4));
    a_Uuid->clockSeqAndNode[4] = (uint8_t)(uuid_parts[0] >> (8 * 3));
    a_Uuid->clockSeqAndNode[5] = (uint8_t)(uuid_parts[0] >> (8 * 2));
    a_Uuid->clockSeqAndNode[6] = (uint8_t)(uuid_parts[0] >> (8 * 1));
    a_Uuid->clockSeqAndNode[7] = (uint8_t)(uuid_parts[0] >> (8 * 0));

    return Tcps_Good;
}

Tcps_StatusCode Tcps_CreateTAInternal(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId)
{
    Tcps_StatusCode status;
    
    TEEC_Result res;
    TEEC_UUID uuid;
    struct tcps_optee_context *optee;
    uint32_t err_origin;
    int s;
   
    TCPS_UNUSED(a_Flags);

    if (!a_TaIdString || !a_pId)
        return Tcps_BadInvalidArgument;

    status = uuid_from_string((char *)a_TaIdString, &uuid);
    if (Tcps_IsBad(status))
        return status;

    optee = malloc(sizeof(*optee));
    if (!optee) {
        return Tcps_BadOutOfMemory;
    }

    s = pthread_mutex_init(&optee->mutex, NULL);
    if (s) {
        status = Tcps_Bad;
        goto out_optee_alloc;
    }

    res = TEEC_InitializeContext(NULL, &optee->ctx);
    if (res != TEEC_SUCCESS) {
        status = Tcps_Bad;
        goto out_mutex;
    }

    res = TEEC_OpenSession(&optee->ctx, &optee->session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        status = Tcps_BadCommunicationError;
        goto out_ctx;
    }

    s = pthread_create(&optee->rpc_thread, NULL, generic_rpc_thread_procedure, optee);
    if (s) {
        status = Tcps_Bad;
        goto out_sess;
    }

    *a_pId = (sgx_enclave_id_t)optee;

    return Tcps_Good;

out_sess:
    TEEC_CloseSession(&optee->session);
out_ctx:
    TEEC_FinalizeContext(&optee->ctx);
out_mutex:
    pthread_mutex_destroy(&optee->mutex);
out_optee_alloc:
    free(optee);
 
    return status;
}

oe_result_t oe_terminate_enclave(
    _In_ oe_enclave_t *enclave)
{
    struct tcps_optee_context *optee;
 
    if (!enclave)
        return OE_INVALID_PARAMETER;

    optee = (struct tpcs_optee_context *)enclave;

    TEEC_CloseSession(&optee->session);
    TEEC_FinalizeContext(&optee->ctx);
    pthread_mutex_destroy(&optee->mutex);
    free(optee);

    return OE_OK;
}
