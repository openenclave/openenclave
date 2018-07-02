// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libc.h>
#include <locale.h>
#include <string.h>

// clang-format off
#define _PTHREAD_IMPL_H
#include "__pthread_self.h"
#include "../3rdparty/musl/musl/src/locale/langinfo.c"
// clang-format on
