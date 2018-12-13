
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stddef.h>
#include <stdint.h>
#include "mixed_t.h"

// This file exists to test that C includes can be successfully included even
// when the cmake executable depends on oelibcxx

void foo_c(int a)
{
    OE_UNUSED(a);
}
