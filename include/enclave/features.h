#ifndef __ELIBC_FEATURES_H
#define __ELIBC_FEATURES_H

#define __ELIBC

#ifndef __GNUC__
# error "This C library must be compiled with GCC"
#endif

#ifndef __x86_64
# error "This C library is for the X86-64 architecture"
#endif

#ifdef __cplusplus
# define __ELIBC_BEGIN extern "C" {
# define __ELIBC_END }
#else
# define __ELIBC_BEGIN
# define __ELIBC_END
#endif

#define __ELIBC_INLINE static __inline__

#if __STDC_VERSION__ >= 199901L || defined(__cplusplus)
# define __inline inline
#endif

#define __NORETURN __attribute__((__noreturn__))

#define __WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((weak, alias(#OLD)))

#define __UNUSED __attribute__((unused))

#define ___CONCAT(X,Y) X##Y
#define __CONCAT(X,Y) ___CONCAT(X,Y)

#define __STATIC_ASSERT(COND) typedef unsigned char \
    __CONCAT(___STATIC_ASSERT, __LINE__)[COND?1:-1] __UNUSED

#endif /* __ELIBC_FEATURES_H */
