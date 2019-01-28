// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Use OE STDC time.h & limits.h defs for MUSL __secs_to_tm.c */
#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include "../../3rdparty/musl/musl/src/time/__secs_to_tm.c"
#include <openenclave/elibc/time.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif
