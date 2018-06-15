// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_OCALLS_H
#define _OE_HOST_OCALLS_H

#include "enclave.h"

void HandlePuts(uint64_t arg_in);
void HandlePrint(uint64_t arg_in);
void HandlePutchar(uint64_t arg_in);
void HandlePutws(uint64_t arg_in);

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out);
void HandleRealloc(uint64_t arg_in, uint64_t* arg_out);
void HandleFree(uint64_t arg);

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWakeWait(oe_enclave_t* enclave, uint64_t arg_in);

void HandleGetQuote(uint64_t arg_in);
void HandleGetQETargetInfo(uint64_t arg_in);

void HandleStrftime(uint64_t arg_in);

void HandleGettimeofday(uint64_t arg_in);

void HandleClockgettime(uint64_t arg_in);

void HandleNanosleep(uint64_t arg_in);

#endif /* _OE_HOST_OCALLS_H */
