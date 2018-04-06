// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_OCALLS_H
#define _OE_HOST_OCALLS_H

#include "enclave.h"

void HandlePuts(uint64_t argIn);
void HandlePrint(uint64_t argIn);
void HandlePutchar(uint64_t argIn);
void HandlePutws(uint64_t argIn);

void HandleMalloc(uint64_t argIn, uint64_t* argOut);
void HandleRealloc(uint64_t argIn, uint64_t* argOut);
void HandleFree(uint64_t arg);

void HandleThreadWait(OE_Enclave* enclave, uint64_t arg);
void HandleThreadWake(OE_Enclave* enclave, uint64_t arg);
void HandleThreadWakeWait(OE_Enclave* enclave, uint64_t argIn);

void HandleInitQuote(uint64_t argIn);
void HandleGetRemoteReport(OE_Enclave* enclave, uint64_t argIn);

void HandleStrftime(uint64_t argIn);

void HandleGettimeofday(uint64_t argIn);

void HandleClockgettime(uint64_t argIn);

void HandleNanosleep(uint64_t argIn);

#endif /* _OE_HOST_OCALLS_H */
