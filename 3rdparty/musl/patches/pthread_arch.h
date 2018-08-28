// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PTHREAD_ARCH_PATCH_H
#define _PTHREAD_ARCH_PATCH_H

struct __pthread* __pthread_self();

#define TP_ADJ(p) (p)

#define MC_PC gregs[REG_RIP]

#endif /* _PTHREAD_ARCH_PATCH_H */
