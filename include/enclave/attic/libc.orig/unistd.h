#ifndef __ELIBC_UNISTD_H
#define __ELIBC_UNISTD_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

void swab(const void *from, void *to, ssize_t n);

int getpagesize(void);

#ifdef __ELIBC_UNSUPPORTED
pid_t getpid(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
pid_t getppid(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
uid_t getuid(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
uid_t geteuid(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
gid_t getgid(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
gid_t getegid(void);
#endif

__ELIBC_END

#endif /* __ELIBC_UNISTD_H */
