#ifndef __OE_LIBCXXRT_STUBS_H
#define __OE_LIBCXXRT_STUBS_H

#define pthread_mutex_lock pthread_mutex_lock_u

#define pthread_mutex_unlock pthread_mutex_unlock_u

#define pthread_cond_wait pthread_cond_wait_u

#define pthread_cond_signal pthread_cond_signal_u

#define dladdr __libcxxrt_dladdr

#define printf printf_u

#define fprintf fprintf_u

#define sched_yield __libcxxrt_sched_yield 

#endif /* __OE_LIBCXXRT_STUBS_H */
