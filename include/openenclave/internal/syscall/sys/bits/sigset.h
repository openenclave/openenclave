// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SIGSET_H
#define _OE_SIGSET_H

#define __OE_SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))

typedef struct
{
    unsigned long int __val[__OE_SIGSET_NWORDS];
} oe_sigset_t;

#endif /* _OE_SIGSET_H */
