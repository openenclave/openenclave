// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_GLOBALS_H
#define OE_GLOBALS_H

#include <openenclave/enclave.h>

#include <tee_internal_api.h>

uint8_t __oe_initialized;
uint32_t __oe_windows_ecall_key;

extern TEE_TASessionHandle __oe_rpc_pta_session;
extern TEE_TASessionHandle __oe_cyres_pta_session;

#endif /* OE_GLOBALS_H */
