# Open Enclave Support for libc

Header | Supported | Comments |
:---:|:---:|:---:|
assert.h | Yes | - |
complex.h | Partial | Unsupported functions: cacos(), cacosh(), cacoshl(), cacosl(), casin(), casinh(), casinhl(), casinl(), csqrt(), csqrtl(), cpow(), cpowf(), cpowl() |
ctype.h | Yes | - |
fenv.h | Yes | - |
float.h | Yes | - |
inttypes.h | partial | Unsupported functions: imaxabs(), imaxdiv()|
locale.h | Partial | Only basic support for C/POSIX locale |
malloc.h | Partial | Unsupported functions: malloc_usable_size() |
math.h | Partial | Unsupported functions: acosh(), asinh(), fmal(), lgamma(), lgammaf(), scalbn(), scalbnf(), scalbnl(), sinh(), sinhl(), tgamma() |
setjmp.h | Yes | - |
signal.h | No | - |
stdatomic.h | No | - |
stdio.h | Partial | All I/O functions implicitly call out to untrusted host. Supported functions: snprintf(), sscanf(),  _vfscanf()*_, vsnprintf(), vsscanf(), sprintf(), vsprintf(), puts(), putchar(), vprintf(), printf(), _fprintf()*_, _getc()*_, _ungetc()*_, _fwrite()*_, _fflush()*_, _fputs()*_, _fputc()*_ |
stdlib.h | Partial | Unsupported functions: div(), imaxabs(), imaxdiv(), ldiv(), lldiv() |
string.h | Partial | Unsupported functions: strerror(), strsignal() |
tgmath.h | Partial | Unsupported functions: acosh(), asinh(), fmal(), lgamma(), lgamma_r(), scalbn(), scalbnf(), scalbnl(), sinh(), sinhl(), tgamma() |
threads.h | Partial | Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. Unsupported functions: pthread_create(), pthread_join() and pthread_detach() |
time.h | Partial | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. Supported functions: time(), gettimeofday(), clock_gettime(), nanosleep(). Please note that clock_gettime() only supports CLOCK_REALTIME  |
uchar.h | Yes | - |
wchar.h | Partial | Supported functions: wcscoll(), wcsxfrm() |
wctype.h | Yes | - |

_* Only has support for the streams stderr and stdout, and does not set ferror_
