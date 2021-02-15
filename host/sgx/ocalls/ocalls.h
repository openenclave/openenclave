// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_SGX_OCALLS_H
#define _OE_HOST_SGX_OCALLS_H

#include "../enclave.h"

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg);
void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg);

#endif /* _OE_HOST_SGX_OCALLS_H */
