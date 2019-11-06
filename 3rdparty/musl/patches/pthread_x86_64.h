// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_PTHREAD_H
#define _OE_MUSL_PATCHES_PTHREAD_H

struct __pthread* __pthread_self();

#define TP_ADJ(p) (p)

#define MC_PC gregs[REG_RIP]

#endif /* _OE_MUSL_PATCHES_PTHREAD_H */
