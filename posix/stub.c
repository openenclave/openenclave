// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "posix_t.h"

/* This stub works around a limitation with edger8r where it requires at
 * least one ECALL definition in the EDL file.
 */
void oe_posix_stub_ecall(void)
{
}
