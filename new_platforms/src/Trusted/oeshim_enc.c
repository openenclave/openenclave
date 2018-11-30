/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

/* Allow deprecated APIs in this file, since we need to test them. */
#define OE_ALLOW_DEPRECATED_APIS

#include <openenclave/enclave.h>
#include <sgx_trts.h>
#include <stdlib.h>
#include "oeoverintelsgx_t.h"
#include <string.h>
#include "../oeresult.h"
#include <sgx_utils.h>
#include <sgx_trts_exception.h>
#include "enclavelibc.h"

oe_result_t oe_call_host(_In_z_ const char* func, _In_ void* args)
{
    // This API is deprecated.
    return OE_FAILURE;
}

oe_result_t oe_call_host_by_address(void (*func)(void*, oe_enclave_t*), void* args)
{
    // This API is deprecated.
    return OE_FAILURE;
}

oe_enclave_t* oe_get_enclave(void)
{
    // This API is deprecated.
    return NULL;
}

bool oe_is_within_enclave(const void* ptr, size_t size)
{
    return sgx_is_within_enclave(ptr, size);
}

bool oe_is_outside_enclave(const void* ptr, size_t size)
{
    return sgx_is_outside_enclave(ptr, size);
}

void oe_abort(void)
{
    abort();
}

const char* oe_result_str(oe_result_t result)
{
    static char message[80];
    snprintf(message, sizeof(message), "Error %d", result);
    return message;
}

oe_result_t oe_random(void* data, size_t size)
{
    sgx_status_t sgxStatus = sgx_read_rand((unsigned char *)data, size);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}

void* oe_host_malloc(size_t size)
{
    void* ptr;
    sgx_status_t sgxStatus = ocall_malloc(&ptr, size);
    return (sgxStatus == SGX_SUCCESS) ? ptr : NULL;
}

void* oe_host_realloc(void* ptr, size_t size)
{
    void* newptr;
    sgx_status_t sgxStatus = ocall_realloc(&newptr, ptr, size);
    return (sgxStatus == SGX_SUCCESS) ? newptr : NULL;
}

void* oe_allocate_ocall_buffer(size_t size)
{
    return oe_malloc(size);
}

void oe_free_ocall_buffer(void* buffer)
{
    oe_free(buffer);
}

oe_result_t ecall_InitializeEnclave(void)
{
    return OE_OK;
}

void* oe_host_calloc(size_t nmemb, size_t size)
{
    void* ptr;
    sgx_status_t sgxStatus = ocall_calloc(&ptr, nmemb, size);
    return (sgxStatus == SGX_SUCCESS) ? ptr : NULL;
}

void oe_host_free(void* ptr)
{
    (void)ocall_free(ptr);
}

char* oe_host_strndup(const char* str, size_t n)
{
    // Find length using memchr in n bytes
    char* ptr = memchr(str, 0, n);
    int len = (ptr == NULL) ? n : (ptr - str);
    char* hostBuffer = (char*)oe_host_malloc(len + 1);

    oe_BufferChunk teeChunk;
    memcpy(teeChunk.buffer, str, len);
    teeChunk.buffer[len] = 0;
    teeChunk.size = len + 1;

    sgx_status_t sgxStatus = ocall_CopyReeMemoryFromBufferChunk(hostBuffer, teeChunk);
    return hostBuffer;
}

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **report_data** parameter.
 *
 * If the *report_buffer* is NULL or *report_size* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @param flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param report_data The report data that will be included in the report.
 * @param report_data_size The size of the **report_data** in bytes.
 * @param opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param opt_params_size The size of the **opt_params** buffer.
 * @param report_buffer The buffer to where the resulting report will be copied.
 * @param report_buffer_size The size of the **report** buffer. This is set to
 * the
 * required size of the report buffer on return.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **report_buffer** buffer is NULL or too
 * small.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v1(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result;
    uint8_t* new_buffer;
    size_t buffer_available;

    if (report_buffer == NULL ||
        report_buffer_size == NULL) {
        return OE_INVALID_PARAMETER;
    }

    buffer_available = *report_buffer_size;
    result = oe_get_report_v2(flags,
                              report_data,
                              report_data_size,
                              opt_params,
                              opt_params_size,
                              &new_buffer,
                              report_buffer_size);
    if (result != OE_OK) {
        return result;
    }

    if (*report_buffer_size > buffer_available) {
        oe_free_report(new_buffer);
        return OE_BUFFER_TOO_SMALL;
    }

    memcpy(report_buffer, new_buffer, *report_buffer_size);
    oe_free_report(new_buffer);
    return OE_OK;
}

void oe_free_report(uint8_t* report_buffer)
{
    oe_free(report_buffer);
}

oe_result_t ecall_get_report(
    uint32_t flags,
    _In_ void* opt_params,
    size_t opt_params_size,
    _Out_writes_bytes_(report_buffer_size) void* report_buffer,
    size_t report_buffer_size,
    _Out_ size_t* report_buffer_size_needed)
{
    uint8_t* new_buffer;
    memset(report_buffer, 0, report_buffer_size);
    oe_result_t result = oe_get_report_v2(flags,
                                          NULL,
                                          0,
                                          opt_params,
                                          opt_params_size,
                                          &new_buffer,
                                          report_buffer_size_needed);
    if (result != OE_OK) {
        return result;
    }
    if (report_buffer_size < *report_buffer_size_needed) {
        oe_free(new_buffer);
        return OE_BUFFER_TOO_SMALL;
    }

    memcpy(report_buffer, new_buffer, *report_buffer_size_needed);
    oe_free(new_buffer);
    return OE_OK;
}

int ecall_verify_report(void* report, size_t report_size)
{
    oe_result_t result = oe_verify_report(report, report_size, NULL);
    return result;
}

typedef struct _oe_over_sgx_exception_handler_entry {
    struct _oe_over_sgx_exception_handler_entry* next;
    struct _oe_over_sgx_exception_handler_entry* prev;
    oe_vectored_exception_handler_t handler;
} oe_over_sgx_exception_handler_entry;

void* g_OEOverSgxExceptionHandle = NULL;
oe_over_sgx_exception_handler_entry g_OEOverSgxExceptionHandlerHead;

int oe_over_sgx_exception_handler(sgx_exception_info_t *info)
{
    oe_context_t context = { 0 };
    oe_exception_record_t record = { 0 };
    switch (info->exception_vector) {
    case SGX_EXCEPTION_VECTOR_DE: /* DIV and DIV instructions */
    case SGX_EXCEPTION_VECTOR_DB: /* For Intel use only */
        record.code = OE_EXCEPTION_DIVIDE_BY_ZERO;
        break;
    case SGX_EXCEPTION_VECTOR_BP: /* INT 3 instruction */
        record.code = OE_EXCEPTION_BREAKPOINT;
        break;
    case SGX_EXCEPTION_VECTOR_BR: /* BOUND instruction */
        record.code = OE_EXCEPTION_BOUND_OUT_OF_RANGE;
        break;
    case SGX_EXCEPTION_VECTOR_UD: /* UD2 instruction or reserved opcode */
        record.code = OE_EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    case SGX_EXCEPTION_VECTOR_MF: /* x87 FPU floating-point or WAIT/FWAIT instruction */
        record.code = OE_EXCEPTION_X87_FLOAT_POINT;
        break;
    case SGX_EXCEPTION_VECTOR_AC: /* Any data reference in memory */
        record.code = OE_EXCEPTION_ACCESS_VIOLATION;
                   // OE_EXCEPTION_PAGE_FAULT
                   // OE_EXCEPTION_MISALIGNMENT
        break;
    case SGX_EXCEPTION_VECTOR_XM: /* SSE/SSE2/SSE3 floating-point instruction */
        record.code = OE_EXCEPTION_SIMD_FLOAT_POINT;
        break;
    default:
        record.code = OE_EXCEPTION_UNKNOWN;
        break;
    }
    if (info->exception_type == SGX_EXCEPTION_HARDWARE) {
        record.flags |= OE_EXCEPTION_FLAGS_HARDWARE;
    } else if (info->exception_type == SGX_EXCEPTION_SOFTWARE) {
        record.flags |= OE_EXCEPTION_FLAGS_SOFTWARE;
    }
    record.context = &context;

    context.flags = record.flags;
#if defined (_M_X64) || defined (__x86_64__)
    record.address = info->cpu_context.rip;
    context.rax = info->cpu_context.rax;
    context.rbx = info->cpu_context.rbx;
    context.rcx = info->cpu_context.rcx;
    context.rdx = info->cpu_context.rdx;
    context.rbp = info->cpu_context.rbp;
    context.rsp = info->cpu_context.rsp;
    context.rdi = info->cpu_context.rdi;
    context.rsi = info->cpu_context.rsi;
    context.r8 = info->cpu_context.r8;
    context.r9 = info->cpu_context.r9;
    context.r10 = info->cpu_context.r10;
    context.r11 = info->cpu_context.r11;
    context.r12 = info->cpu_context.r12;
    context.r13 = info->cpu_context.r13;
    context.r14 = info->cpu_context.r14;
    context.r15 = info->cpu_context.r15;
    context.rip = info->cpu_context.rip;
    context.mxcsr = info->cpu_context.rflags;
    /* context.basic_xstate = ... */
#else
    record.address = info->cpu_context.eip;
    context.rax = info->cpu_context.eax;
    context.rbx = info->cpu_context.ebx;
    context.rcx = info->cpu_context.ecx;
    context.rdx = info->cpu_context.edx;
    context.rbp = info->cpu_context.ebp;
    context.rsp = info->cpu_context.esp;
    context.rdi = info->cpu_context.edi;
    context.rsi = info->cpu_context.esi;
    context.rip = info->cpu_context.eip;
    context.mxcsr = info->cpu_context.eflags;
    /* context.basic_xstate = ... */
#endif

    oe_over_sgx_exception_handler_entry* entry;
    for (entry = g_OEOverSgxExceptionHandlerHead.next;
         entry != &g_OEOverSgxExceptionHandlerHead;
         entry = entry->next) {
        uint64_t result = entry->handler(&record);
        if (result != 0) {
            return (int)result;
        }
    }
    return 0;
}

oe_over_sgx_exception_handler_entry* FindExceptionEntry(
    oe_vectored_exception_handler_t vectored_handler)
{
    /* Find in doubly-linked list. */
    oe_over_sgx_exception_handler_entry* entry;
    for (entry = g_OEOverSgxExceptionHandlerHead.next;
        entry != &g_OEOverSgxExceptionHandlerHead;
        entry = entry->next) {
        if (entry->handler == vectored_handler) {
            return entry;
        }
    }
    return NULL;
}

/* Note that the Intel SGX SDK docs explain:
 *  "Custom exception handling is only supported in hardware mode.
 *   Although the exception handlers can be registered in simulation mode,
 *   the exceptions cannot be caught and handled within the enclave."
 */
oe_result_t oe_add_vectored_exception_handler(
    bool is_first_handler,
    oe_vectored_exception_handler_t vectored_handler)
{
    if (g_OEOverSgxExceptionHandle == NULL) {
        g_OEOverSgxExceptionHandle = sgx_register_exception_handler(
            TRUE,
            oe_over_sgx_exception_handler);
        g_OEOverSgxExceptionHandlerHead.next = &g_OEOverSgxExceptionHandlerHead;
        g_OEOverSgxExceptionHandlerHead.prev = &g_OEOverSgxExceptionHandlerHead;
        g_OEOverSgxExceptionHandlerHead.handler = NULL;
    }

    /* Check for duplicate. */
    oe_over_sgx_exception_handler_entry* entry = FindExceptionEntry(vectored_handler);
    if (entry != NULL) {
        return OE_INVALID_PARAMETER;
    }

    entry = oe_malloc(sizeof(oe_over_sgx_exception_handler_entry));
    if (entry == NULL) {
        return OE_OUT_OF_MEMORY;
    }
    entry->handler = vectored_handler;

    /* Add to doubly-linked list. */
    if (is_first_handler) {
        entry->next = g_OEOverSgxExceptionHandlerHead.next;
        g_OEOverSgxExceptionHandlerHead.next = entry;
        entry->prev = entry->next->prev;
        entry->next->prev = entry;
    } else {
        entry->prev = g_OEOverSgxExceptionHandlerHead.prev;
        g_OEOverSgxExceptionHandlerHead.prev = entry;
        entry->next = entry->prev->next;
        entry->prev->next = entry;
    }

    return OE_OK;
}

oe_result_t oe_remove_vectored_exception_handler(
    oe_vectored_exception_handler_t vectored_handler)
{
    /* Find in doubly-linked list. */
    oe_over_sgx_exception_handler_entry* entry = FindExceptionEntry(vectored_handler);
    if (entry == NULL) {
        return OE_INVALID_PARAMETER;
    }

    /* Remove from doubly-linked list. */
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;

    if (g_OEOverSgxExceptionHandlerHead.next == &g_OEOverSgxExceptionHandlerHead) {
        /* List is now empty. */
        int result = sgx_unregister_exception_handler(g_OEOverSgxExceptionHandle);
        if (result == 0) {
            return OE_FAILURE;
        }
        g_OEOverSgxExceptionHandle = NULL;
    }
    return OE_OK;
}

/* Get a symmetric encryption key derived from the specified policy and coupled
 * to the enclave platform.
 */
oe_result_t oe_get_seal_key_by_policy_v1(
    _In_ oe_seal_policy_t seal_policy,
    _Out_writes_bytes_(*key_buffer_size) uint8_t* key_buffer,
    _Inout_ size_t* key_buffer_size,
    _Out_writes_bytes_(*key_info_size) uint8_t* key_info,
    _Inout_ size_t* key_info_size)
{
    uint8_t* key = NULL;
    size_t key_size = 0;
    uint8_t* info = NULL;
    size_t info_size = 0;
    oe_result_t result = oe_get_seal_key_by_policy_v2(seal_policy,
                                                      &key,
                                                      &key_size,
                                                      &info,
                                                      &info_size);
    if (result != OE_OK) {
        return result;
    }

    if (*key_info_size < info_size || *key_buffer_size < key_size) {
        *key_info_size = info_size;
        *key_buffer_size = key_size;
        oe_free_key(key, info);
        return OE_BUFFER_TOO_SMALL;
    }

    memcpy(key_buffer, key, key_size);
    if (key_info != NULL) {
        memcpy(key_info, info, info_size);
    }
    *key_info_size = info_size;
    *key_buffer_size = key_size;

    oe_free_key(key, info);
    return OE_OK;
}

void oe_free_key(
    _In_ uint8_t* key,
    _In_ uint8_t* info)
{
    oe_free(key);
    oe_free(info);
}

oe_result_t oe_get_seal_key_v1(
    _In_reads_bytes_(key_info_size) const uint8_t* key_info,
    _In_ size_t key_info_size,
    _Out_writes_bytes_(*key_buffer_size) uint8_t* key_buffer,
    _Inout_ size_t* key_buffer_size)
{
    size_t key_size = 0;
    uint8_t* key = NULL;
    oe_result_t result = oe_get_seal_key_v2(key_info,
                                            key_info_size,
                                            &key,
                                            &key_size);
    if (result != OE_OK) {
        return result;
    }

    if (*key_buffer_size < key_size) {
        *key_buffer_size = key_size;
        oe_free_key(key, NULL);
        return OE_BUFFER_TOO_SMALL;
    }

    *key_buffer_size = key_size;
    memcpy(key_buffer, key, key_size);

    oe_free_key(key, NULL);
    return OE_OK;
}

typedef void(*oe_ecall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

#undef __oe_ecalls_table
#undef __oe_ecalls_table_size
extern oe_ecall_func_t __oe_ecalls_table[];
extern size_t __oe_ecalls_table_size;

size_t ecall_v2(
    _In_ uint32_t func,
    _In_reads_bytes_(inBufferSize) const void* in_buffer,
    _In_ size_t in_buffer_size,
    _Out_writes_bytes_(outBufferSize) void* out_buffer,
    _In_ size_t out_buffer_size)
{
    size_t outBytesWritten = 0;

    if (__oe_ecalls_table == NULL || func >= __oe_ecalls_table_size) {
        return 0;
    }

    __oe_ecalls_table[func](
        in_buffer,
        in_buffer_size,
        out_buffer,
        out_buffer_size,
        &outBytesWritten);

    return outBytesWritten;
}

extern oe_ecall_func_t __oe_internal_ecalls_table[];
extern size_t __oe_internal_ecalls_table_size;

size_t ecall_internal(
    _In_ uint32_t func,
    _In_reads_bytes_(inBufferSize) const void* in_buffer,
    _In_ size_t in_buffer_size,
    _Out_writes_bytes_(outBufferSize) void* out_buffer,
    _In_ size_t out_buffer_size)
{
    size_t outBytesWritten = 0;

    if (__oe_internal_ecalls_table == NULL || func >= __oe_internal_ecalls_table_size) {
        return 0;
    }

    __oe_internal_ecalls_table[func](
        in_buffer,
        in_buffer_size,
        out_buffer,
        out_buffer_size,
        &outBytesWritten);

    return outBytesWritten;
}

void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* function)
{
    printf("Assertion failed: %s (%s: %s: %d)\n", expr, file, function, line);
    oe_abort();
}
