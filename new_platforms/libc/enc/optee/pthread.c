#include <pthread.h>
#include <errno.h>

int pthread_cond_signal(pthread_cond_t *cond)
{
    return 0;
}

int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
    return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, 
    const pthread_mutexattr_t *attr)
{
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t* m)
{
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t* m)
{
    return 0;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*))
{
    return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
    return NULL;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
    return 0;
}

int pthread_once(pthread_once_t *once_control, 
    void (*init_routine)(void))
{
    init_routine();
}
