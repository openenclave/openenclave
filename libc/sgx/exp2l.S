// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Rename the expm1l() defined in exp2l.s and use the definition in expm1l.c
#define expm1l __unused_expm1_l
#include "../../3rdparty/musl/musl/src/math/x86_64/exp2l.s"
