// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crypto.h"

// Initialize various modules in well-defined order.
// TODO: This causes hang.
// Possibly due to CPUID throwing exception during start.
// bool g_Initialize = InitializeCrypto();