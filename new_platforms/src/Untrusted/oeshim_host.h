/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

typedef struct {
    size_t nr_ocall;
    const oe_ocall_func_t* call_addr;
} ocall_table_v2_t;

extern ocall_table_v2_t g_ocall_table_v2;
extern ocall_table_v2_t g_internal_ocall_table_v2;

oe_result_t ocall_demux(
    _In_ uint32_t func,
    _In_reads_bytes_(inBufferSize) const void* in_buffer,
    _In_ size_t in_buffer_size,
    _Out_writes_bytes_(outBufferSize) void* out_buffer,
    _In_ size_t out_buffer_size,
    _Out_ size_t* out_bytes_written,
    _In_ ocall_table_v2_t* ocall_table);
