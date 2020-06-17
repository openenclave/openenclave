// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SETJMP_H
#define _OE_SETJMP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/defs.h>

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

#define ___OE_JMP_BUF _oe_jmp_buf
#define __OE_JMP_BUF oe_jmp_buf
#include <openenclave/corelibc/bits/jmp_buf.h>
#undef ___OE_JMP_BUF
#undef __OE_JMP_BUF

int oe_setjmp(oe_jmp_buf* env) OE_RETURNS_TWICE;

void oe_longjmp(oe_jmp_buf* env, int val);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define ___OE_JMP_BUF _jmp_buf
#define __OE_JMP_BUF jmp_buf
#include <openenclave/corelibc/bits/jmp_buf.h>
#undef ___OE_JMP_BUF
#undef __OE_JMP_BUF

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
