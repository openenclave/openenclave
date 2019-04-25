// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <stdlib.h>

OE_NO_RETURN void exit(int code)
{
    _Exit(code);
}
