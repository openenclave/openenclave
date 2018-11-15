/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_HOST_H
# error include <openenclave/host.h> instead of including oehost.h directly
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OE_SIMULATE_OPTEE
# include "optee/Untrusted/Simulator/oehost.h"
#endif

#include <tcps.h>

#include <sgx_eid.h>

#include <stddef.h>
typedef intptr_t ssize_t;
#include <openenclave/bits/result.h>

#ifndef __in_ecount
#include "sal_unsup.h"
#endif

/* The caller is responsible for freeing the buffer after calling this. */
void* TcpsCreateReeBuffer(_In_ int a_BufferSize);

oe_result_t TcpsGetReeBuffer(
    _In_ void* a_hReeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize);

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer);

/* The caller is responsible for freeing the buffer after calling this. */
oe_result_t
TcpsPushDataToTeeBuffer(
    _In_ sgx_enclave_id_t eid,
    _In_reads_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phTeeBuffer);
void TcpsFreeTeeBuffer(_In_ void* a_hTeeBuffer);

/* OP-TEE only allows one thread per TA to be in an ecall.  Even if it has
 * an ocall in progress, that ecall must complete before another ecall
 * can enter the TA.  SGX, on the other hand, would allow a second ecall
 * to enter.  So to allow them to function identically, apps should wrap
 * ecalls in the following mutex Acquire/Release calls.  In the future,
 * if we have our own code generator instead of sgx_edger8r, these could
 * be automatic instead of requiring manual coding effort to call.
 */
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
oe_result_t oe_acquire_enclave_mutex(_In_ oe_enclave_t* enclave);
void oe_release_enclave_mutex(_In_ oe_enclave_t* enclave);

#ifdef __cplusplus
}
#endif
