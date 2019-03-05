// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#pragma GCC diagnostic ignored "-Wsign-conversion"
#define __strchrnul __oe_strchrnul
#define strlen oe_strlen
#define UCHAR_MAX OE_UCHAR_MAX
#define weak_alias(old, new) /* empty */
#include "../../3rdparty/musl/musl/src/string/strchrnul.c"
