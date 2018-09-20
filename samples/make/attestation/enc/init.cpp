// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crypto.h"

// Initialize various modules in well-defined order.
bool g_initialize = InitializeCrypto();
