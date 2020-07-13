// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_OCALLS_H
#define _OE_HOST_OCALLS_H

#include <stdint.h>

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out);
void HandleFree(uint64_t arg);

void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out);

void oe_handle_wake_host_worker(uint64_t arg_in);

#endif /* _OE_HOST_OCALLS_H */
