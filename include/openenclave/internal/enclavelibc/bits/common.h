// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_COMMON_H
#define _ENCLAVELIBC_COMMON_H

#include "../../enclavelibc.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define CHAR_BIT 8

OE_EXTERNC_BEGIN

typedef long time_t;
typedef __builtin_va_list va_list;

OE_EXTERNC_END

#endif /* _ENCLAVELIBC_COMMON_H */
