# Open Enclave Support for libc

Header | Supported | Comments |
:---:|:---:|:---|
assert.h | Yes | - |
complex.h | Partial | **Unsupported functions:** cacos(), cacosh(), cacoshl(), cacosl(), casin(), casinh(), casinhl(), casinl(), csqrt(), csqrtl(), cpow(), cpowf(), cpowl() |
ctype.h | Partial | Only basic support for C/POSIX locale. |
errno.h | Yes | - |
execinfo.h | Partial | **Supported functions:** backtrace(), backtrace_symbols(). <br> Enclaves must be compiled with `-fno-omit-frame-pointer` for accurate backtraces. |
fenv.h | Yes | - |
float.h | Yes | - |
inttypes.h | Yes | - |
iso646.h | Yes | - |
limits.h | Yes | - |
locale.h | Partial | Only basic support for C/POSIX locale |
malloc.h | Partial | - |
math.h | Partial | **Unsupported functions:** fmal(), tgamma() |
setjmp.h | Yes | - |
signal.h | No | - |
stdalign.h | No | - |
stdarg.h | Yes | - |
stdatomic.h | No | - |
stdbool.h | Yes | - |
stddef.h | Yes | - |
stdint.h | Yes | - |
stdio.h | Partial | All I/O functions implicitly call out to untrusted host. <br> **Supported functions:** snprintf(), sscanf(),  _vfscanf()*_, vsnprintf(), vsscanf(), sprintf(), vsprintf(), puts(), putchar(), vprintf(), printf(), _fprintf()*_, _getc()*_, _ungetc()*_, _fwrite()*_, _fflush()*_, _fputs()*_, _fputc()*_ <br> _* Only has support for the streams stderr and stdout, and does not set ferror_ |
stdlib.h | Yes | - |
stdnoreturn.h | No | - |
string.h | Partial | Only basic support for C/POSIX locale. |
tgmath.h | Partial | **Unsupported functions:** fmal(), scalbn(), scalbnf(), scalbnl(), tgamma() |
pthread.h | Partial | Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. <br> **Supported functions:** <br> _- General:_ pthread_self(), pthread_equal(), pthread_once() <br> _- Spinlock:_ pthread_spin_init(), pthread_spin_lock(), pthread_spin_unlock(), pthread_spin_destroy() <br> _- Mutex:_ pthread_mutexattr_init(), pthread_mutexattr_settype(), pthread_mutexattr_destroy(), pthread_mutex_init(), pthread_mutex_lock(), pthread_mutex_trylock(), pthread_mutex_unlock(), pthread_mutex_destroy() <br> _- RW Lock:_ pthread_rwlock_init(), pthread_rwlock_rdlock(), pthread_rwlock_wrlock(), pthread_rwlock_unlock(), pthread_rwlock_destroy() <br> _- Cond:_ pthread_cond_init(), pthread_cond_wait(), pthread_cond_timedwait(), pthread_cond_signal(), pthread_cond_broadcast(), pthread_cond_destroy() <br> _- Thread local storage:_ pthread_key_create(), pthread_key_delete(), pthread_setspecific(), pthread_getspecific() |
threads.h | No | - |
time.h | Partial | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported functions:** time(), gettimeofday(), clock_gettime(), nanosleep(). _Please note that clock_gettime() only supports CLOCK_REALTIME_ |
uchar.h | Yes | - |
wchar.h | Partial | Only basic support for C/POSIX locale. <br> **Unsupported functions:** <br> - All I/O (e.g. swprintf()) <br> - All multi-byte & wide string conversions (e.g. mbrtowc()) |
wctype.h | Yes | - |

