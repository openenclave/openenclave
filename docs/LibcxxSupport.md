# Open Enclave Support for libcxx

Open Enclave uses a a version of the [LLVM libc++](https://libcxx.llvm.org/) library adapted for an enclave environment. It is tested up to the C++17 standard, and supports most of the features in that standard. In general, the following kinds of features may not be supported.
- Features that require system calls to the untrusted host.
    - Some of these features, such as file I/O, require linking in the optional [oesyscall libraries](/syscall/README.md) and do not work by default.
    - Others, such as thread creation, are simply not supported in the the enclave runtime.
- Equivalent standard C library functions that are not supported, as documented in [LibcSupport.md](LibcSupport.md)

For more details on the libcxx testing in Open Enclave, refer to this [document](/tests/libcxx/README.md).

## Concepts Library
Header | Supported | Comments |
:---:|:---:|:---|
concepts | No | Header is not provided, C++20 is not yet supported. |

## Coroutines Library
Header | Supported | Comments |
:---:|:---:|:---|
coroutines | No | Header is not provided, C++20 is not yet supported. |

## Utilities Library
Header | Supported | Comments |
:---:|:---:|:---|
any | Yes | Supported as part of C++17. |
bitset | Yes | - |
compare | No | C++20 is not yet supported. |
csetjmp | Yes | - |
csignal | No | - |
cstdarg | Yes | - |
cstddef | Yes | - |
cstdlib | Partial | **Unsupported functions:** at_quick_exit(), quick_exit() |
ctime | Partial | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported functions:** time(), gettimeofday(), clock_gettime(), nanosleep(). _Please note that clock_gettime() only supports CLOCK_REALTIME_ |
chrono | Partial | Supported up to C++17. All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported classes:** system_clock, treat_as_floating_point, duration_values |
functional | Yes | Supported up to C++17. |
initializer_list | Yes | Supported as part of C++11. |
optional | Yes | Supported as part of C++17. |
tuple | Yes | Supported up to C++17. |
type_traits | Yes | Supported up to C++17. |
typeindex | Yes | Supported as part of C++11. |
typeinfo | Yes | - |
utility | Yes | - |
variant | Yes | Supported as part of C++17. |
version | No | C++20 is not yet supported. |

#### Dynamic Memory Management
Header | Supported | Comments |
:---:|:---:|:---|
new | Yes | - |
memory | Yes | - |
scoped_allocator | Yes | - |
memory_resource | Yes | Supported as part of C++17. The header is under `experimental/` |

#### Numeric Limits
Header | Supported | Comments |
:---:|:---:|:---|
cfloat | Yes | - |
cinttypes | Yes | Supported as part of C++11. |
climits | Yes | - |
cstdint | Yes | Supported as part of C++11. |
limits | Yes | - |

#### Error Handling
Header | Supported | Comments |
:---:|:---:|:---|
cassert | Yes | - |
exception | Yes | Supported up to C++17. |
stdexcept | Yes | - |
system_error | Yes | Supported as part of C++11. |
cerrno | Yes | - |

## Strings Library
Header | Supported | Comments |
:---:|:---:|:---|
cctype | Partial | Only basic support for C/POSIX locale. |
charconv | Yes | Supported as part of C++17. |
cuchar | No | Header is not provided. |
cwchar | Partial | Only basic support for C/POSIX locale. <br> **Unsupported functions:** <br> - All I/O (e.g. swprintf()). <br> - All multi-byte & wide string conversions (e.g. mbrtowc()). |
cwctype | Partial | Only basic support for C/POSIX locale. |
cstring | Partial | Only basic support for C/POSIX locale. |
format | No | C++20 is not yet supported. |
string | Yes | Supported up to C++17. |
string_view | Yes | Supported as part of C++17. |

## Containers Library
Header | Supported | Comments |
:---:|:---:|:---|
array | Yes | Supported up to C++17. |
deque | Yes | Supported up to C++17. |
forward_list | Yes | Supported up to C++17. |
list | Yes | Supported up to C++17. |
map | Yes | Supported up to C++17. |
queue | Yes | Supported up to C++17. |
set | Yes | Supported up to C++17. |
stack | Yes | Supported up to C++17. |
unordered_map | Yes | Supported up to C++17. |
unordered_set | Yes | Supported up to C++17. |
vector | Yes | Supported up to C++17. |
span | No | C++20 is not yet supported. |

## Iterators Library
Header | Supported | Comments |
:---:|:---:|:---|
iterator | Yes | Supported up to C++17. |

## Ranges Library
Header | Supported | Comments |
:---:|:---:|:---|
ranges | No | Header is not provided, C++20 is not yet supported. |

## Algorithms Library
Header | Supported | Comments |
:---:|:---:|:---|
algorithm | Yes | Supported up to C++17. |

## Numerics Library
Header | Supported | Comments |
:---:|:---:|:---|
bit | No | Header is not provided, C++20 is not yet supported. |
cfenv | Yes | Supported as part of C++11. |
cmath | Partial | fmal() and tgamma() fail on long-double precision tests. |
complex | Yes | Supported up to C++17. |
numeric | Yes | Supported up to C++17. |
random | Partial | Supported as part of C++11. <br> **Unsupported class:** random_device. |
ratio | Yes | Supported as part of C++11. |
valarray | Yes | - |

## Input/output Library
Header | Supported | Comments |
:---:|:---:|:---|
cstdio | Partial | All I/O functions implicitly call out to untrusted host. <br> **Supported functions:** snprintf(), sscanf(),  _vfscanf()*_, vsnprintf(), vsscanf(), sprintf(), vsprintf(), puts(), putchar(), vprintf(), printf(), _fprintf()*_, _getc()*_, _ungetc()*_, _fwrite()*_, _fflush()*_, _fputs()*_, _fputc()*_. <br> _* Only has support for the streams stderr and stdout, and does not set ferror_. | |
fstream | No | - |
iomanip | Partial | **Unsupported functions:** get_money(), put_money(), get_time(), put_time() |
ios | Yes | Only basic support for C/POSIX locale. |
iosfwd | Partial | See other headers for which forward declarations are supported. |
iostream | Yes | - |
istream | Yes | - |
ostream | Yes | - |
strstream | No | Header is provided, but deprecated as of C++98. |
sstream | Yes | - |
streambuf | Yes | - |
syncstream | No | Header is not provided, C++20 is not yet supported. |

## Localization Library
Header | Supported | Comments |
:---:|:---:|:---|
clocale | Partial | Only basic support for C/POSIX locale. |
codecvt | Partial |  Only basic support for C locale. Supported as part of C++11. |
locale | Partial | Only basic support for C locale. |

## Regular Expressions Library
Header | Supported | Comments |
:---:|:---:|:---|
regex | Yes | Supported up to C++17. |

## Atomic Operations Library
Header | Supported | Comments |
:---:|:---:|:---|
atomic | Yes | Supported up to C++17. |

## Thread Support Library
Header | Supported | Comments |
:---:|:---:|:---|
barrier | No | C++20 is not yet supported. |
condition_variable | Partial | Supported as part of C++11. Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. |
future | Partial | Supported as part of C++11. Asynchronous invocations are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. |
latch | No | C++20 is not yet supported. |
mutex | Partial | Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. <br> **Unsupported classes:** timed_mutex, recursive_timed_mutex, scoped_lock (C++17). |
semaphore | No | C++20 is not yet supported. |
shared_mutex | No | - |
stop_token | No | C++20 is not yet supported. |
thread | No | - |

## Filesystem Library
Header | Supported | Comments |
:---:|:---:|:---|
filesystem | No | - |

## C Compatibility Headers
Header | Provided | Comments |
:---:|:---:|:---|
assert.h | No | - |
complex.h | Yes | Empty header, includes &lt;complex&gt;. <br> &lt;ccomplex&gt; is also provided. |
ctype.h | Yes | - |
errno.h | Yes | - |
fenv.h | No | - |
float.h | Yes | - |
inttypes.h | Yes | - |
iso646.h | No | Meaningless in C++, although &lt;ciso646&gt; is provided instead. |
limits.h | Yes | - |
locale.h | Yes | - |
math.h | Yes | - |
setjmp.h | Yes | - |
signal.h | No | - |
stdalign.h | No | Meaningless in C++. |
stdarg.h | No | - |
stdbool.h | Yes | Meaningless in C++. |
stddef.h | Yes | - |
stdint.h | Yes | - |
stdio.h | Yes | - |
stdlib.h | Yes | - |
string.h | Yes | - |
time.h | No | - |
tgmath.h | Yes | Empty header, includes &lt;complex&gt; and &lt;cmath&gt;. <br> &lt;ctgmath&gt; is also provided. |
uchar.h | No | - |
wchar.h | Yes | - |
wctype.h | Yes | - |
