// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Disabling clang formatting as it incorrectly reorders the includes
// Goal of this test is to route the oe_thread calls to pthread with
// definitions in the local thread.h

// clang-format off
#include "thread.h"
#include "enc_oethread.cpp"
// clang-format on
