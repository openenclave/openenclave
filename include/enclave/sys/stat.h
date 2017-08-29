#ifndef __ELIBC_SYS_STAT_H
#define __ELIBC_SYS_STAT_H

#include "../features.h"

__ELIBC_BEGIN

typedef struct stat __stat;

#ifdef __ELIBC_UNSUPPORTED
int stat(const char *pathname, struct stat *buf);
#endif

#ifdef __ELIBC_UNSUPPORTED
int fstat(int fd, struct stat *buf);
#endif

#ifdef __ELIBC_UNSUPPORTED
int lstat(const char *pathname, struct stat *buf);
#endif

__ELIBC_END

#endif /* __ELIBC_SYS_STAT_H */
