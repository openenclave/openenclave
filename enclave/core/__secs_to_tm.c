// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* Define this to satisfy compiler for unused function in time_impl.h */
typedef struct __locale_struct* locale_t;
#include "../../3rdparty/musl/musl/src/include/features.h"

#include "../../3rdparty/musl/musl/src/time/__secs_to_tm.c"
