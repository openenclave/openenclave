#ifndef __ELIBC_STDDEF_H
#define __ELIBC_STDDEF_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#define offsetof(type, member) __builtin_offsetof(type, member)

__ELIBC_END

#endif /* __ELIBC_STDDEF_H */
