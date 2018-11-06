/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef UNTRUSTED_CODE
# error oehost.h should only be included with UNTRUSTED_CODE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SIMULATE_TEE
# include "optee/Untrusted/Simulator/oehost.h"
#endif

#include <tcps.h>

#include <sgx_eid.h>

#include <stddef.h>


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

#ifdef __cplusplus
}
#endif
