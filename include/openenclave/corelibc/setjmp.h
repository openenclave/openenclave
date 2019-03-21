// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SETJMP_H
#define _OE_SETJMP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

typedef struct _oe_jmp_buf
{
#include <openenclave/corelibc/bits/jmp_buf.h>
} oe_jmp_buf;

int oe_setjmp(oe_jmp_buf* env);

void oe_longjmp(oe_jmp_buf* env, int val);

#if defined(OE_NEED_STDC_NAMES)

typedef struct _jmp_buf
{
#include <openenclave/corelibc/bits/jmp_buf.h>
} jmp_buf;

OE_INLINE int setjmp(jmp_buf* env)
{
    return oe_setjmp((oe_jmp_buf*)env);
}

OE_INLINE void longjmp(jmp_buf* env, int val)
{
    return oe_longjmp((oe_jmp_buf*)env, val);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_SETJMP_H */
