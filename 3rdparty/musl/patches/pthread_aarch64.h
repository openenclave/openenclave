// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_PTHREAD_H
#define _OE_MUSL_PATCHES_PTHREAD_H

struct __pthread* __pthread_self();

#define TLS_ABOVE_TP
#define GAP_ABOVE_TP 16
#define TP_ADJ(p) ((char*)(p) + sizeof(struct pthread))

#define MC_PC pc

#endif /* _OE_MUSL_PATCHES_PTHREAD_H */
