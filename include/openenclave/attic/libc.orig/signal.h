#ifndef __ELIBC_SIGNAL_H
#define __ELIBC_SIGNAL_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#ifdef __ELIBC_UNSUPPORTED
int sigfillset(sigset_t *set);
#endif

__ELIBC_END

#endif /* __ELIBC_SIGNAL_H */
