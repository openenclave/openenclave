// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdlib.h>

#include "optee_u.h"

void* oe_calloc_ocall(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}
