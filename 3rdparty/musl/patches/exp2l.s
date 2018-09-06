// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Rename expm1l to __unused_expm1l (use the C version from expm1l.c instead).
// The exp21 assembly function from __exp2l.s is still needed.
#define expm1l __unused_expm1l
include "__exp2l.s"
