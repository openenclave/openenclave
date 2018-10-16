/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <tcps_t.h>
#include <stdbool.h>
#include "../../include/openenclave/enclave.h"
#define _UINTPTR_T_DEFINED_
#define _UINTPTR_T_DEFINED
#define _SIZE_T_DEFINED_
#define _SIZE_T_DEFINED
#define _PTRDIFF_T_DEFINED_
#define _PTRDIFF_T_DEFINED
#define _SSIZE_T_DEFINED_
#include <sgx.h>

#undef OE_ECALL
#define OE_ECALL

#undef oe_assert
#define oe_assert TCPS_ASSERT

#ifdef __cplusplus
extern "C" {
#endif

/* TODO: this is being put into edger8r/enclave.h */
oe_result_t oe_call_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

#ifdef __cplusplus
}
#endif
