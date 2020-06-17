// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../xstate.h"
#include "Windows.h"

uint64_t oe_get_xfrm()
{
    return (GetEnabledXStateFeatures());
}
