// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_SYSCALL_ARCH_H
#define _OE_MUSL_PATCHES_SYSCALL_ARCH_H

#include <openenclave/internal/syscall_decls.h>

#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)

#undef VDSO_USEFUL
#undef VDSO_CGT_SYM
#undef VDSO_CGT_VER
#undef VDSO_GETCPU_SYM
#undef VDSO_GETCPU_VER

#define OE_SYSCALL_SEPARATE_FUNCTIONS

#endif /* _OE_MUSL_PATCHES_SYSCALL_ARCH_H */
