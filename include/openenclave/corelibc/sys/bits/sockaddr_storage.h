// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
sa_family_t ss_family;
char __ss_padding[128 - sizeof(long) - sizeof(sa_family_t)];
unsigned long __ss_align;
// clang-format on
