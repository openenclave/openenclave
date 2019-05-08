// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "other_t.h"

MyOther ecall_other(MyOther o)
{
    return MyOther{o.x + 1};
}
