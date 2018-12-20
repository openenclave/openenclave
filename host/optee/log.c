// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/trace.h>

void oe_log(log_level_t level, const char* fmt, ...)
{
    OE_UNUSED(level);
    OE_UNUSED(fmt);
}
