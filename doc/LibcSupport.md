# Open Enclave Support for libc

Header | Supported? | Comments |
:---:|:---:|:---:| 
assert.h | Yes | - |
complex.h | Partial | Unsupported functions: cpow(), cpowf(), cpowl() |
ctype.h | Yes | - |
errno.h | ? | ? |
fenv.h | Yes | - |
float.h | Yes | - |
locale.h | Partial | Only basic support for C/POSIX locale |
malloc.h | Partial | Unsupported functions: aligned_alloc(), lite_malloc(), malloc_usable_size()
math.h | Partial | Unsupported functions: acosh(), asinh(), fmal(), j0(), jn(), jnf(), lgamma(), lgammaf(), lgammaf_r(), lgamma_r(), scalbn(), scalbnf(), scalbnl(), sinh(), sinhl(), tgamma(), y0(), y0f(), ynf() |
setjmp.h | Yes | - |
signal.h | No | - |
stdio.h | Partial | Supported functions: snprintf(), vasprintf(), sscanf(), swprintf(), asprintf(), _vfprintf()*_, _vfscanf()*_, _vfwprintf()*_, vsnprintf(), vsscanf(), vswprintf(), _fputwc()*_, sprintf(), vsprintf(), puts(), putchar(), vprintf(), printf(), _fprintf()*_, _getc()*_, _ungetc()*_, _fwrite()*_, _fflush()*_ |
stdlib.h | Partial | Unsupported functions: div(), ecvt(), fcvt(), gcvt(), imaxabs(), imaxdiv(), ldiv(), lldiv() |
string.h | Partial | Unsupported functions: strerror(), strsignal() |
threads.h | Partial | Supported functions: pthread_getspecific(), pthread_setspecific(), pthread_key_delete(), pthread_key_create(), pthread_cond_destroy(), pthread_cond_broadcast(), pthread_cond_signal(), pthread_cond_wait(), pthread_cond_init(), pthread_rwlock_destroy(), pthread_rwlock_unlock(), pthread_rwlock_wrlock(), pthread_rwlock_rdlock(), pthread_rwlock_init(), pthread_mutex_destroy(), pthread_mutex_unlock(), pthread_mutex_trylock(), pthread_mutex_lock(), pthread_mutex_init(),  pthread_spin_init(), pthread_spin_lock(), pthread_spin_init(), pthread_self(), pthread_equal() |
time.h | Partial | Supported functions: time(), gettimeofday(), clock_gettime(), strftime(), strftime_l(), nanosleep() |
wchar.h | Partial | Supported functions: wcscoll(), wcscoll_l(), wcsxfrm(), wcsxfrm_l() |

_* Only has support for the streams stderr and stdout_
