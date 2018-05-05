// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "pingpong_t.h"

OE_EXTERNC void Ping(const char* in, char* out)
{
    Pong(in, out);
}
