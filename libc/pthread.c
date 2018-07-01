// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Need 'struct timespec' for pthread function definitions below */
#define OE_ENCLAVELIBC_NEED_STDC_NAMES
#include <openenclave/internal/enclavelibc/time.h>
#undef OE_ENCLAVELIBC_NEED_STDC_NAMES

#include <openenclave/internal/enclavelibc/pthread.h>

/* Emit pthread-function definitions by suppressing inlining */
#undef OE_ENCLAVELIBC_INLINE
#define OE_ENCLAVELIBC_INLINE
#include <openenclave/internal/enclavelibc/bits/pthread.h>
