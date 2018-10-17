/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef UNTRUSTED_CODE
# error tcps_u.h should only be included with UNTRUSTED_CODE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SIMULATE_TEE
# include "optee/Untrusted/Simulator/tcps_u.h"
#endif

#include <tcps.h>

#include <sgx_eid.h>

/* OP-TEE only allows one thread per TA to be in an ecall.  Even if it has
 * an ocall in progress, that ecall must complete before another ecall
 * can enter the TA.  SGX, on the other hand, would allow a second ecall
 * to enter.  So to allow them to function identically, apps should wrap
 * ecalls in the following mutex Acquire/Release calls.  In the future,
 * if we have our own code generator instead of sgx_edger8r, these could
 * be automatic instead of requiring manual coding effort to call.
 */
Tcps_StatusCode TcpsAcquireTAMutex( _In_ sgx_enclave_id_t eid);
Tcps_Void TcpsReleaseTAMutex( _In_ sgx_enclave_id_t eid);

#define oe_acquire_enclave_mutex(enclave) TcpsAcquireTAMutex((sgx_enclave_id_t)enclave)
#define oe_release_enclave_mutex(enclave) TcpsReleaseTAMutex((sgx_enclave_id_t)enclave)

/* The caller is responsible for freeing the buffer after calling this. */
void* TcpsCreateReeBuffer(_In_ int a_BufferSize);

Tcps_StatusCode TcpsGetReeBuffer(
    _In_ void* a_hReeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize);

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer);

/* The caller is responsible for freeing the buffer after calling this. */
Tcps_StatusCode
TcpsPushDataToTeeBuffer(
    _In_ sgx_enclave_id_t eid,
    _In_reads_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phTeeBuffer);
void TcpsFreeTeeBuffer(_In_ void* a_hTeeBuffer);

#if !defined(NDEBUG) || defined(EDEBUG)
#define TCPS_ENCLAVE_FLAG_DEBUG ((int)1)
#else
#define TCPS_ENCLAVE_FLAG_DEBUG ((int)0)
#endif

Tcps_StatusCode Tcps_CreateTA(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId);

Tcps_StatusCode Tcps_DestroyTA(
    _In_ sgx_enclave_id_t a_Id);

#ifdef __cplusplus
}
#endif
