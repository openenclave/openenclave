// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_SGX_OCALLS_H
#define _OE_HOST_SGX_OCALLS_H

#include "enclave.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out);
void HandleRealloc(uint64_t arg_in, uint64_t* arg_out);
void HandleFree(uint64_t arg);

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWakeWait(oe_enclave_t* enclave, uint64_t arg_in);

void HandleGetQuote(uint64_t arg_in);
void HandleGetQETargetInfo(uint64_t arg_in);
void HandleGetQuoteRevocationInfo(uint64_t arg_in);
void HandleGetQuoteEnclaveIdentityInfo(uint64_t arg_in);

void oe_handle_backtrace_symbols(oe_enclave_t* enclave, uint64_t arg);
void oe_handle_log(oe_enclave_t* enclave, uint64_t arg);

#endif /* _OE_HOST_SGX_OCALLS_H */
