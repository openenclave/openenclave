// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "other_u.h"

MyOther ocall_other(MyOther o)
{
    return MyOther{o.x + 1};
}
