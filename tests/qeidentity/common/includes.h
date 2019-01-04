// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _COMMON_INCLUDES_H_
#define _COMMON_INCLUDES_H_

#include "../../../common/tcbinfo.h"
#include "../../../host/quote.h"

#ifndef OE_USE_LIBSGX
// the following empty type was added to avoid build error in host/tests_u.h
typedef struct
{
} oe_parsed_qe_identity_info_t;
#endif
#endif
