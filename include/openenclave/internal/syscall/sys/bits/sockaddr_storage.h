// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_SOCKADDR_STORAGE
{
    oe_sa_family_t ss_family;
    char __ss_padding[128 - sizeof(long) - sizeof(oe_sa_family_t)];
    unsigned long __ss_align;
};
