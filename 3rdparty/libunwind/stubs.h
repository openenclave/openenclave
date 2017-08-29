#ifndef __OE_LIBUNWIND_STUBS_H
#define __OE_LIBUNWIND_STUBS_H

#define pthread_mutex_lock pthread_mutex_lock_u

#define pthread_mutex_unlock pthread_mutex_unlock_u

#define mmap __libunwind_mmap

#define munmap __libunwind_munmap

#define msync __libunwind_msync

#define mincore __libunwind_mincore

#endif /* __OE_LIBUNWIND_STUBS_H */
