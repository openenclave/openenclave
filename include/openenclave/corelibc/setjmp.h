// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SETJMP_H
#define _OE_SETJMP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#define __OE_STRUCT_JMP_BUF _oe_jmp_buf
#define __OE_TYPEDEF_JMP_BUF oe_jmp_buf
#include <openenclave/corelibc/bits/jmp_buf.h>
#undef __OE_STRUCT_JMP_BUF
#undef __OE_TYPEDEF_JMP_BUF

int oe_setjmp(oe_jmp_buf* env);

void oe_longjmp(oe_jmp_buf* env, int val);

#if defined(OE_NEED_STDC_NAMES)

#define __OE_STRUCT_JMP_BUF _jmp_buf
#define __OE_TYPEDEF_JMP_BUF jmp_buf
#include <openenclave/corelibc/bits/jmp_buf.h>
#undef __OE_STRUCT_JMP_BUF
#undef __OE_TYPEDEF_JMP_BUF

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
