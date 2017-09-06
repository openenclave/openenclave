#ifndef __ELIBC_SCHED_H
#define __ELIBC_SCHED_H

#include <features.h>
#include <bits/alltypes.h>

#ifdef __ELIBC_UNSUPPORTED
int sched_yield(void);
#endif

#endif /* __ELIBC_SCHED_H */
