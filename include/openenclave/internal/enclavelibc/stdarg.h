// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDARG_H
#define _ENCLAVELIBC_STDARG_H

#include "bits/common.h"

#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_copy __builtin_va_copy

#endif /* _ENCLAVELIBC_STDARG_H */
