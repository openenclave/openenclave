// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>

#pragma GCC diagnostic ignored "-Wsign-conversion"
#define strcspn oe_strcspn
#define __strchrnul oe_strchrnul
#include "../../3rdparty/musl/musl/src/string/strcspn.c"
