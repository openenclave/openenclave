// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../xstate.h"
#include "Windows.h"

uint64_t oe_get_xfrm()
{
    return (GetEnabledXStateFeatures());
}
