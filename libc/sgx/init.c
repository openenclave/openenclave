// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/libc/init.h>
#include "libc.h"
#include "stdio_impl.h"

void oe_libc_initialize(void)
{
    /* In MUSL, locks are initialized for standard streams the first time a
       thread is created, in pthread_create.c.
       Since OE has pre-allocated number of thread, pthread_create is too late
       to mark libc as multi threaded. Therefore, libc initialization is done
       here instead. This also allows oecore to control exactly when libc is
       initialized.
    */
    libc.threaded = 1;
    // MUSL also maintains libc.threads_minus_1 variable to keep track of
    // number of running threads. That variable is used to decide whether
    // locks are needed. OE, instead, always locks since it is not possible
    // to easily manage that variable from within oecore.
    libc.need_locks = 1;
    stdin->lock = 0;
    stdout->lock = 0;
    stderr->lock = 0;
}

bool oe_test_libc_is_initialized(void)
{
    return (libc.threaded == 1) && (libc.need_locks == 1) &&
           (__atomic_load_n(&stdin->lock, __ATOMIC_SEQ_CST) >= 0) &&
           (__atomic_load_n(&stdout->lock, __ATOMIC_SEQ_CST) >= 0) &&
           (__atomic_load_n(&stderr->lock, __ATOMIC_SEQ_CST) >= 0);
}
