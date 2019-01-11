// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _COMMON_INCLUDES_H_
#define _COMMON_INCLUDES_H_

#include "../../../common/sgx/tcbinfo.h"
#include "../../../host/sgx/quote.h"

#ifndef OE_USE_LIBSGX

typedef struct
{
} oe_tcb_level_t;
typedef struct
{
} oe_parsed_tcb_info_t;

#endif

#endif
