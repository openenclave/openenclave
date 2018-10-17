/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include <sgx_trts.h>
#include <stdlib.h>
#include "TcpsCalls_t.h"
#include <string.h>
#include "../oeresult.h"
#include <sgx_utils.h>
#include <sgx_trts_exception.h>

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

/* TODO: delete once callers are updated */
int Tcps_FillRandom(
    _Out_writes_bytes_all_(len) void* ptr,
    _In_ size_t len)
{
    return oe_random(ptr, len);
}

/* TODO: delete once callers are updated */
int FillRandom(
    _Out_writes_bytes_all_(len) void* ptr,
    _In_ size_t len)
{
    return oe_random(ptr, len);
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

    BufferChunk teeChunk;
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
oe_result_t oe_get_report(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    sgx_report_t sgxReport = { 0 };
    sgx_report_data_t* sgxReportData = NULL;
    sgx_target_info_t* sgxTargetInfo = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    
    if (report_data_size > 0) {
        sgxReportData = (sgx_report_data_t*)report_data;
    }
    if (opt_params_size > 0) {
        sgxTargetInfo = (sgx_target_info_t*)opt_params;
    }

    if (report_data_size != 0 &&
        report_data_size != SGX_REPORT_DATA_SIZE) {
        return OE_INVALID_PARAMETER;
    }
    if (opt_params_size != 0 &&
        opt_params_size != sizeof(sgx_target_info_t)) {
        return OE_INVALID_PARAMETER;
    }
    if (report_buffer == NULL ||
        *report_buffer_size < sizeof(sgx_report_t)) {
        *report_buffer_size = sizeof(sgx_report_t);
        return OE_BUFFER_TOO_SMALL;
    }

    sgxStatus = sgx_create_report(sgxTargetInfo, sgxReportData, &sgxReport);
    if (sgxStatus != SGX_SUCCESS) {
        oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
        return oeResult;
    }

    if (sgxTargetInfo == NULL) {
        // When a report is generated with NULL target info, the MAC won't be valid
        // but it will return the target info, so call it again with the target info
        // returned.
        sgx_target_info_t targetInfo2 = { 0 };
        targetInfo2.attributes = sgxReport.body.attributes;
        targetInfo2.mr_enclave = sgxReport.body.mr_enclave;
        targetInfo2.misc_select = sgxReport.body.misc_select;
        sgxStatus = sgx_create_report(&targetInfo2, sgxReportData, &sgxReport);
        if (sgxStatus != SGX_SUCCESS) {
            oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
            return oeResult;
        }
    }

    memcpy(report_buffer, &sgxReport, sizeof(sgxReport));
    *report_buffer_size = sizeof(sgxReport);

    return OE_OK;
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t oeResult = OE_OK;
    if (report_size != sizeof(sgx_report_t)) {
        return OE_INVALID_PARAMETER;
    }
    if (parsed_report != NULL) {
        oeResult = oe_parse_report(report, report_size, parsed_report);
        if (oeResult != OE_OK) {
            return oeResult;
        }
    }
    const sgx_report_t* sgxReport = (sgx_report_t*)report;
    sgx_status_t sgxStatus = sgx_verify_report(sgxReport);
    oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}

GetReport_Result ecall_get_report(
    uint32_t flags,
    buffer1024 opt_params,
    size_t opt_params_size)
{
    GetReport_Result result = { 0 };
    result.report_buffer_size = sizeof(result.report_buffer);
    result.result = oe_get_report(flags,
                                  NULL,
                                  0,
                                  opt_params.buffer,
                                  opt_params_size,
                                  result.report_buffer,
                                  &result.report_buffer_size);
    return result;
}

int ecall_verify_report(buffer1024 report, size_t report_size)
{
    oe_result_t result = oe_verify_report(report.buffer, report_size, NULL);
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

    entry = malloc(sizeof(oe_over_sgx_exception_handler_entry));
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
oe_result_t oe_get_seal_key_by_policy(
    _In_ oe_seal_policy_t seal_policy,
    _Out_writes_bytes_(*key_buffer_size) uint8_t* key_buffer,
    _Inout_ size_t* key_buffer_size,
    _Out_writes_bytes_(*key_info_size) uint8_t* key_info,
    _Inout_ size_t* key_info_size)
{
    if (*key_info_size < sizeof(sgx_key_request_t) ||
        *key_buffer_size < sizeof(sgx_key_128bit_t)) {
        *key_info_size = sizeof(sgx_key_request_t);
        *key_buffer_size = sizeof(sgx_key_128bit_t);
        return OE_BUFFER_TOO_SMALL;
    }
    *key_info_size = sizeof(sgx_key_request_t);

    sgx_report_t sgxReport = { 0 };
    sgx_status_t sgxStatus = sgx_create_report(NULL, NULL, &sgxReport);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }

    sgx_key_request_t key_request = { 0 };
    key_request.key_name = SGX_KEYSELECT_SEAL;
    switch (seal_policy) {
    case OE_SEAL_POLICY_UNIQUE:
        key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
        break;
    case OE_SEAL_POLICY_PRODUCT:
        key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;
        break;
    default:
        return OE_INVALID_PARAMETER;
    }
    key_request.isv_svn = sgxReport.body.isv_svn;
    key_request.cpu_svn = sgxReport.body.cpu_svn;
    key_request.attribute_mask = sgxReport.body.attributes;
    oe_result_t oeResult = oe_random(&key_request.key_id, sizeof(key_request.key_id));
    if (oeResult != OE_OK) {
        return oeResult;
    }

    if (key_info != NULL) {
        memcpy(key_info, &key_request, sizeof(key_request));
    }

    oeResult = oe_get_seal_key((uint8_t*)&key_request, sizeof(key_request), key_buffer, key_buffer_size);
    return oeResult;
}

/* Get a symmetric encryption key from the enclave platform using existing key information. */
oe_result_t oe_get_seal_key(
    _In_reads_bytes_(key_info_size) const uint8_t* key_info,
    _In_ size_t key_info_size,
    _Out_writes_bytes_(*key_buffer_size) uint8_t* key_buffer,
    _Inout_ size_t* key_buffer_size)
{
    if (*key_buffer_size < sizeof(sgx_key_128bit_t)) {
        *key_buffer_size = sizeof(sgx_key_128bit_t);
        return OE_BUFFER_TOO_SMALL;
    }
    if (key_info_size < sizeof(sgx_key_request_t)) {
        key_info_size = sizeof(sgx_key_request_t);
        return OE_INVALID_PARAMETER;
    }
    *key_buffer_size = sizeof(sgx_key_128bit_t);

    sgx_key_request_t* key_request = (sgx_key_request_t*)key_info;
    sgx_status_t sgxStatus = sgx_get_key(key_request, (sgx_key_128bit_t*)key_buffer);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}

typedef struct {
    size_t nr_ecall;
    struct { oe_call_t call_addr; uint8_t is_priv; } ecall_table[1];
} ecall_table_v2_t;

ecall_table_v2_t* g_ecall_table_v2 = NULL;

callV2_Result ecall_v2(uint32_t func, buffer4096 inBuffer, size_t inBufferSize)
{
    callV2_Result result;

    if (g_ecall_table_v2 == NULL || func > g_ecall_table_v2->nr_ecall) {
        result.outBufferSize = 0;
        return result;
    }

    oe_call_t call = g_ecall_table_v2->ecall_table[func].call_addr;
    call(inBuffer.buffer,
         inBufferSize,
         result.outBuffer,
         sizeof(result.outBuffer),
         &result.outBufferSize);

    return result;
}

oe_result_t oe_call_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    callV2_Result result;
    buffer4096 inBufferStruct;
    if (input_buffer_size > sizeof(inBufferStruct)) {
        return OE_INVALID_PARAMETER;
    }
    COPY_BUFFER(inBufferStruct, input_buffer, input_buffer_size);
    sgx_status_t sgxStatus = ocall_v2(&result,
                                      function_id,
                                      inBufferStruct,
                                      input_buffer_size);
    if (sgxStatus == SGX_SUCCESS) {
        if (result.outBufferSize > output_buffer_size) {
            return OE_BUFFER_TOO_SMALL;
        }
        memcpy(output_buffer, result.outBuffer, result.outBufferSize);
        *output_bytes_written = result.outBufferSize;
    }
    return GetOEResultFromSgxStatus(sgxStatus);
}
