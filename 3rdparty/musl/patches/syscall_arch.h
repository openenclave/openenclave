// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _SYSCALL_ARCH_PATCH_H
#define _SYSCALL_ARCH_PATCH_H

#include "__syscall_arch.h"

#undef VDSO_USEFUL
#undef VDSO_CGT_SYM
#undef VDSO_CGT_VER
#undef VDSO_GETCPU_SYM
#undef VDSO_GETCPU_VER

#endif /* _SYSCALL_ARCH_PATCH_H */
