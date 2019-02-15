// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STACK_ALLOC_H
#define _OE_STACK_ALLOC_H

/**
 * Allocates space on the stack frame of the caller.
 *
 * This function allocates **SIZE** bytes of space on the stack frame of the
 * caller. The allocated space is automatically freed when the calling
 * function returns. If the stack overflows, the behavior is undefined.
 *
 * @param SIZE The number of bytes to allocate.
 *
 * @returns Returns the address of the allocated space.
 *
 */

// __builtin_alloca is appropriate for both gcc and clang.
// For MSVC, we will probably want _malloca from <malloc.h>.
#define oe_stack_alloc(SIZE) __builtin_alloca(SIZE)

#endif /* _OE_STACK_ALLOC_H */
