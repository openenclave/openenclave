// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_INIT_H
#define OE_INIT_H

#include <openenclave/enclave.h>
#include "td.h"

void OE_InitializeEnclave();

void OE_CallInitFunctions(void);

void OE_CallFiniFunctions(void);

#endif /* OE_INIT_H */
