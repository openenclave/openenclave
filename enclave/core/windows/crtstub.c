// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crttypes.h"

/*
 * When -NODEFAULTLIB is specified, linker will generate "unresolved external"
 * for these CRT symbols. Adding the stub here to workaround the issue.
 *
 * N.B. The actual location is a compiler-generated array. Whatever declared
 *      here is discared, except for the symbol.
 */

extern _CRTALLOC(".CRT$XIA") _PIFV __xi_a = 0;
extern _CRTALLOC(".CRT$XIZ") _PIFV __xi_z = 0; /* C initializers */
extern _CRTALLOC(".CRT$XCA") _PVFV __xc_a = 0;
extern _CRTALLOC(".CRT$XCZ") _PVFV __xc_z = 0; /* C++ initializers */
extern _CRTALLOC(".CRT$XPA") _PVFV __xp_a = 0;
extern _CRTALLOC(".CRT$XPZ") _PVFV __xp_z = 0; /* C pre-terminators */
extern _CRTALLOC(".CRT$XTA") _PVFV __xt_a = 0;
extern _CRTALLOC(".CRT$XTZ") _PVFV __xt_z = 0;
