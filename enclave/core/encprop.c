// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

//
// Declare an invalid oeinfo to ensure .oeinfo section exists
// - This object won't be linked if enclave has the macro defined.
// - If enclave does't have the macro defined, it must go through
//   oesign to update the stucture, which would override the value.
//

OE_SET_ENCLAVE_SGX(
    OE_UINT16_MAX,
    OE_UINT16_MAX,
    false,
    OE_UINT16_MAX,
    OE_UINT16_MAX,
    OE_UINT16_MAX);
