// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "syscall_t.h"

/* This stub works around a limitation with edger8r where it requires at
 * least one ECALL definition in the EDL file.
 */
void oe_syscall_stub_ecall(void)
{
}
