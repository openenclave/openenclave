// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libc.h>
#include <locale.h>
#include <string.h>

#define _PTHREAD_IMPL_H
#include "../3rdparty/musl/musl/src/locale/langinfo.c"
#include "__pthread_self.h"
