// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGX_HOST_QUOTE_PROVIDER_H
#define _OE_SGX_HOST_QUOTE_PROVIDER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/report.h>
#include "../common/qeidentity.h"
#include "../common/revocation.h"

OE_EXTERNC_BEGIN

oe_result_t oe_initialize_quote_provider(void);

OE_EXTERNC_END

#endif // _OE_SGX_HOST_QUOTE_PROVIDER_H
