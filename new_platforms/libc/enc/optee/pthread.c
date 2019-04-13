#include <errno.h>
#include <pthread.h>
#include "locale_impl.h"
#include "pthread_impl.h"

#ifdef pthread_equal
#undef pthread_equal
#endif

#ifdef pthread
#undef pthread
#endif

//
// Self
//

struct __pthread self = { 0 };
pthread_t __pthread_self()
{
    self.locale = C_LOCALE;
    return &self;
}
pthread_t pthread_self() { return __pthread_self; }

//
// Cond Vars
//

int pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr) { return 0; }
int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex) { return 0; }
int pthread_cond_timedwait(pthread_cond_t* cond, pthread_mutex_t* mutex, const struct timespec* ts) { return 0; }
int pthread_cond_signal(pthread_cond_t* cond) { return 0; }
int pthread_cond_broadcast(pthread_cond_t *cond) { return 0; }
int pthread_cond_destroy(pthread_cond_t* cond) { return 0; }

//
// Mutexes
//

int pthread_mutex_init(pthread_mutex_t *mutex,  const pthread_mutexattr_t *attr) { return 0; }
int pthread_mutex_lock(pthread_mutex_t* m) { return 0; }
int pthread_mutex_trylock(pthread_mutex_t* m) { return 0; }
int pthread_mutex_unlock(pthread_mutex_t* m) { return 0; }
int pthread_mutex_destroy(pthread_mutex_t* m) { return 0; }

//
// Mutex Attrs
//

int pthread_mutexattr_init(pthread_mutexattr_t* attr) { return 0; }
int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type) { return 0; }
int pthread_mutexattr_destroy(pthread_mutexattr_t* attr) { return 0; }

//
// Keys
//

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*)) { return 0; }
void *pthread_getspecific(pthread_key_t key) { return NULL; }
int pthread_setspecific(pthread_key_t key, const void *value) { return 0; }

//
// Threads
//


int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg) { abort(); while(1); }
int pthread_join(pthread_t thread, void** retval) { abort(); while(1); }
int pthread_detach(pthread_t thread) { abort(); while(1); }
int pthread_equal(pthread_t thread1, pthread_t thread2) { return thread1 == thread2; }

//
// Once
//

int pthread_once(pthread_once_t *once_control,  void (*init_routine)(void)) { init_routine(); }
