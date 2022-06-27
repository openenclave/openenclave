// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_PTHREAD_H
#define _OE_MUSL_PATCHES_PTHREAD_H

struct __pthread* __get_tp();

#define TLS_ABOVE_TP
#define GAP_ABOVE_TP 16

#define MC_PC pc

#endif /* _OE_MUSL_PATCHES_PTHREAD_H */
