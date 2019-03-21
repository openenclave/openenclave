// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdlib.h>

_Noreturn void exit(int code)
{
    _Exit(code);
}
