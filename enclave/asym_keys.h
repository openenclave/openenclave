// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_ASYM_KEYS_H
#define _OE_ENCLAVE_ASYM_KEYS_H

#include <openenclave/enclave.h>

void oe_handle_get_public_key_by_policy(uint64_t arg_in);

void oe_handle_get_public_key(uint64_t arg_in);

#endif /* OE_ENCLAVE_ASYM_KEYS_H */
