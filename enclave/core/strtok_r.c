// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#define strspn oe_strspn
#define strcspn oe_strcspn
#define strtok_r oe_strtok_r
#include "../../3rdparty/musl/musl/src/string/strtok_r.c"
