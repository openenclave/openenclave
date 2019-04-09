// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LIBUNWIND_COMMON_H
#define _OE_LIBUNWIND_COMMON_H

#include "libunwind-common.inc"

#undef unw_step
#define unw_step __libunwind_unw_step

int __libunwind_unw_step(unw_cursor_t* cursor);

#endif /* _OE_LIBUNWIND_COMMON_H */
