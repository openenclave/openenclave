// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_OCALLS_H
#define _OE_HOST_OCALLS_H

#include <stdint.h>

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out);
void HandleFree(uint64_t arg);

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg);

void oe_handle_sleep(uint64_t arg_in);
void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out);

#endif /* _OE_HOST_OCALLS_H */
