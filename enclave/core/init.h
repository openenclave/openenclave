// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_INIT_H
#define OE_INIT_H

#include <openenclave/enclave.h>
#include "td.h"

void oe_initialize_enclave();

void oe_call_init_functions(void);

void oe_call_fini_functions(void);

bool oe_apply_relocations(void);

#endif /* OE_INIT_H */
