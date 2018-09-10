// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_SYSCALL_ARCH_H
#define _OE_MUSL_PATCHES_SYSCALL_ARCH_H

#include "__syscall_arch.h"

#undef VDSO_USEFUL
#undef VDSO_CGT_SYM
#undef VDSO_CGT_VER
#undef VDSO_GETCPU_SYM
#undef VDSO_GETCPU_VER

#define SYSCALL_NO_INLINE

#endif /* _OE_MUSL_PATCHES_SYSCALL_ARCH_H */
