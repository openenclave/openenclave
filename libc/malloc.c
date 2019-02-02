// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/stdlib.h>
#include <openenclave/internal/enclavelibc.h>

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#if defined(OE_INLINE)
#undef OE_INLINE
#define OE_INLINE
#endif
#define OE_USE_MUSL_DEFS
#include <openenclave/elibc/bits/malloc.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif
