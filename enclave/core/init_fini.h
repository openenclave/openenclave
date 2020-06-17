// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_INIT_FINI_H
#define OE_INIT_FINI_H

#include <openenclave/enclave.h>

void oe_call_init_functions(void);

void oe_call_fini_functions(void);

#endif /* OE_INIT_FINI_H */
