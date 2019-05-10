// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Use OE STDC time.h & limits.h defs for MUSL __secs_to_tm.c */
#define OE_NEED_STDC_NAMES

/* Define this to satisfy compiler for unused function in time_impl.h */
typedef struct __locale_struct* locale_t;
#include "../../3rdparty/musl/musl/src/include/features.h"

#include "../../3rdparty/musl/musl/src/time/__secs_to_tm.c"
