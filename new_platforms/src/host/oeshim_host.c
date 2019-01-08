/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifndef _MSC_VER
#include "sal_unsup.h"
#include "stdext.h"
#else
#include <Windows.h>
#endif
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <openenclave/host.h>
#include "oeshim_host.h"
#include "oeinternal_u.h"
#undef oe_create_enclave

ocall_table_v2_t g_ocall_table_v2 = { 0 };
ocall_table_v2_t g_internal_ocall_table_v2 = { 0 };

/* TODO: this flag should be per enclave */
int g_serialize_ecalls = FALSE;

oe_result_t oe_create_enclave_helper(
    _In_z_ const char* path,
    uint32_t flags,
    _Outptr_ oe_enclave_t** enclave);

oe_result_t oe_create_internal_enclave(
    _In_z_ const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    _In_reads_bytes_(config_size) const void* config,
    uint32_t config_size,
    _In_reads_(ocall_table_size) const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    _Outptr_ oe_enclave_t** enclave)
{
    OE_UNUSED(enclave);
    OE_UNUSED(path);
    OE_UNUSED(type);
    OE_UNUSED(flags);
    OE_UNUSED(config);
    OE_UNUSED(config_size);

    /* Just save the ocall table. */
    g_internal_ocall_table_v2.nr_ocall = ocall_table_size;
    g_internal_ocall_table_v2.call_addr = ocall_table;

    return OE_OK;
}

oe_result_t oe_create_enclave(
    _In_z_ const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    _In_reads_bytes_(configSize) const void* config,
    uint32_t config_size,
    _In_reads_(ocall_table_size) const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    _Outptr_ oe_enclave_t** enclave)
{
    *enclave = NULL;

    OE_UNUSED(type);
    OE_UNUSED(config);
    OE_UNUSED(config_size);

    g_ocall_table_v2.nr_ocall = ocall_table_size;
    g_ocall_table_v2.call_addr = ocall_table;

    if (flags & OE_ENCLAVE_FLAG_SERIALIZE_ECALLS) {
        g_serialize_ecalls = TRUE;
        flags &= ~OE_ENCLAVE_FLAG_SERIALIZE_ECALLS;
    } else {
        g_serialize_ecalls = FALSE;
    }
    int serialize_ecall = g_serialize_ecalls;

    // Load the enclave.
    oe_enclave_t* eid;
    oe_result_t result = oe_create_enclave_helper(path, flags, &eid);
    if (result != OE_OK) {
        return result;
    }

    // Initialize the internal OCALL table.
    result = oe_create_oeinternal_enclave(NULL, 0, 0, NULL, 0, NULL);
    if (result != OE_OK) {
        return result;
    }

    // Make sure we can call into the enclave.  This also registers the
    // OCALL handler, which OP-TEE needs.
    if (serialize_ecall) {
        oe_acquire_enclave_mutex(eid);
    }
    result = ecall_InitializeEnclave(eid, &result);
    if (serialize_ecall) {
        oe_release_enclave_mutex(eid);
    }

    if (result != OE_OK) {
        oe_terminate_enclave(eid);
        return result;
    }

    *enclave = eid;
    return OE_OK;
}

oe_result_t oe_call_enclave(oe_enclave_t* enclave, const char* func, void* args)
{
    // This API is deprecated.
    return OE_FAILURE;
}

oe_result_t oe_ecall(oe_enclave_t* enclave, uint16_t func, uint64_t argIn, uint64_t* argOut)
{
    // This API is deprecated.
    return OE_FAILURE;
}

const char* oe_result_str(oe_result_t result)
{
    static char message[80];
    sprintf_s(message, sizeof(message), "Error %d", result);
    return message;
}

void* ocall_malloc(size_t size)
{
    return malloc(size);
}

void* ocall_realloc(_In_ void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void* ocall_calloc(_In_ size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

#ifdef _MSC_VER
char* strndup(_In_ char* str, size_t n)
{
    n = strlen(str) > n ? n : strlen(str);
    char* result = (char*)malloc(n + 1);
    if (!result)
        return NULL;
    strncpy(result, str, n);
    result[n] = '\0';
    return result;
}
#endif  // _MSC_VER

char* ocall_strndup(_In_ char* str, size_t n)
{
    return strndup(str, n);
}

void ocall_free(_In_ void* ptr)
{
    free(ptr);
}

oe_result_t oe_get_report_v1(
    _In_ oe_enclave_t* enclave,
    uint32_t flags,
    _In_reads_opt_(opt_params_size) const void* opt_params,
    size_t opt_params_size,
    _Out_ uint8_t* report_buffer,
    _Inout_ size_t* report_buffer_size)
{
    int serialize_ecall = g_serialize_ecalls;

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }

    oe_result_t result;
    oe_result_t error = ecall_get_report(
        enclave,
        &result,
        flags,
        (void*)opt_params,
        opt_params_size,
        report_buffer,
        *report_buffer_size,
        report_buffer_size);

    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }

    if (error != OE_OK) {
        return error;
    }
    return result;
}

oe_result_t oe_get_report_v2(
    _In_ oe_enclave_t* enclave,
    uint32_t flags,
    _In_reads_opt_(opt_params_size) const void* opt_params,
    size_t opt_params_size,
    _Outptr_ uint8_t** report_buffer,
    _Out_ size_t* report_buffer_size)
{
    *report_buffer = NULL;
    *report_buffer_size = 0;

    int serialize_ecall = g_serialize_ecalls;
    for (;;) {
        if (serialize_ecall) {
            oe_acquire_enclave_mutex(enclave);
        }

        oe_result_t result;
        size_t size_needed;
        oe_result_t error = ecall_get_report(
            enclave,
            &result,
            flags,
            (void*)opt_params,
            opt_params_size,
            *report_buffer,
            *report_buffer_size,
            &size_needed);
        if (serialize_ecall) {
            oe_release_enclave_mutex(enclave);
        }

        if (error != OE_OK) {
            return error;
        }
        if (result != OE_BUFFER_TOO_SMALL) {
            return result;
        }

        // We don't have a big enough buffer, so get ready to call again.
        free(*report_buffer);
        *report_buffer = malloc(size_needed);
        if (*report_buffer == NULL) {
            return OE_OUT_OF_MEMORY;
        }
        *report_buffer_size = size_needed;
    }
}

void oe_free_report(_In_ uint8_t* report_buffer)
{
    free(report_buffer);
}

oe_result_t oe_verify_report(
    _In_ oe_enclave_t* enclave,
    _In_reads_(report_size) const uint8_t* report,
    size_t report_size,
    _Out_opt_ oe_report_t* parsed_report)
{
    oe_result_t oeResult;
    int serialize_ecall = g_serialize_ecalls;

    if (parsed_report != NULL) {
        oeResult = oe_parse_report(report, report_size, parsed_report);
        if (oeResult != OE_OK) {
            return oeResult;
        }
    }

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }
    oe_result_t returned_result;
    oeResult = ecall_verify_report(enclave, &returned_result, (void*)report, report_size);
    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }
    if (oeResult != OE_OK) {
        return oeResult;
    }

    return returned_result;
}

/**
 * Gets the public key of an enclave.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] seal_policy The seal policy used to determine which key to get.
 * @param[out] key_buffer Upon success, this points to the public key.
 * @param[out] key_buffer_size Upon success, this contains the size of the *key_buffer* buffer.
 * @param[out] key_info Reserved for future use.  Must pass NULL.
 * @param[out] key_info_size Reserved for future use.  Must pass NULL.
 *
 * @retval OE_OK The public key was successfully obtained.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_enclave_t* enclave,
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    /* TODO: to be implemented */
    return OE_FAILURE;
}

void oe_free_public_key(
    uint8_t* key_buffer,
    uint8_t* key_info)
{
    free(key_buffer);
    free(key_info);
}

oe_result_t ocall_demux(
    uint32_t func,
    _In_reads_bytes_(inBufferSize) const void* in_buffer,
    size_t in_buffer_size,
    _Out_writes_bytes_(outBufferSize) void* out_buffer,
    size_t out_buffer_size,
    _Out_ size_t* out_bytes_written,
    _In_ ocall_table_v2_t* ocall_table)
{
    if (func >= ocall_table->nr_ocall) {
        return OE_INVALID_PARAMETER;
    }

    oe_ocall_func_t call = ocall_table->call_addr[func];

    call(in_buffer,
         in_buffer_size,
         out_buffer,
         out_buffer_size,
         out_bytes_written);

    return OE_OK;
}
