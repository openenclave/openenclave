// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/defs.h>

/* See syscall/stub.c */
void oe_optee_stub_ecall(void)
{
}

/* These are functions referenced by libutee that are left out while compiling
 * it for inclusion in the SDK.
 */

void _oe_trace_set_level(int level)
{
    OE_UNUSED(level);
}

void _oe_malloc_add_pool(void* buf, size_t len)
{
    OE_UNUSED(buf);
    OE_UNUSED(len);
}

void oe__TEE_MathAPI_Init(void)
{
}

OE_WEAK_ALIAS(_oe_trace_set_level, trace_set_level);
OE_WEAK_ALIAS(_oe_malloc_add_pool, malloc_add_pool);
OE_WEAK_ALIAS(oe__TEE_MathAPI_Init, _TEE_MathAPI_Init);
