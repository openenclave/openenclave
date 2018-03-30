// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SIGN_H
#define _OE_SIGN_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include "sha.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

OE_Result OE_SignEnclave(
    const OE_SHA256* mrenclave,
    const char* pemData,
    size_t pemSize,
    SGX_SigStruct* sigstruct);

OE_EXTERNC_END

#endif /* _OE_SIGN_H */
