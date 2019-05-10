# Open Enclave Support for libcxx

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
any | No | C++17 is not yet supported. |
bitset | Yes | - |
compare | No | C++20 is not yet supported. |
csetjmp | Yes | - |
csignal | No | - |
cstdarg | Yes | - |
cstddef | Yes | - |
cstdlib | Partial | **Unsupported functions:** at_quick_exit(), quick_exit() |
ctime | Partial | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported functions:** time(), gettimeofday(), clock_gettime(), nanosleep(). _Please note that clock_gettime() only supports CLOCK_REALTIME_ |
chrono | Partial | Supported as part of C++11. All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported classes:** system_clock, treat_as_floating_point, duration_values |
functional | No | - |
initializer_list | Yes | Supported as part of C++11. |
optional | No | C++17 is not yet supported. |
tuple | Partial | Supported as part of C++11, known issues with apply() template. |
type_traits | Yes | Supported as part of C++11. |
typeindex | Yes | Supported as part of C++11. |
typeinfo | Yes | - |
utility | Partial | **Unsupported template:** as_const. |
variant | No | C++17 is not yet supported. |
version | No | C++20 is not yet supported. |

#### Dynamic Memory Management
Header | Supported | Comments |
:---:|:---:|:---|
new | Yes | - |
memory | Partial | Supported as part of C++11, so features such uninitialized_move and destroy_at are not yet supported. |
scoped_allocator | Yes | - |
memory_resource | No | Header is not provided, C++17 is not yet supported. |

#### Numeric Limits
Header | Supported | Comments |
:---:|:---:|:---|
cfloat | Yes | - |
cinttypes | Partial | Supported as part of C++11. <br> **Unsupported functions:** imaxabs(), imaxdiv() |
climits | Yes | - |
cstdint | Yes | Supported as part of C++11. |
limits | Yes | - |

#### Error Handling
Header | Supported | Comments |
:---:|:---:|:---|
cassert | Yes | - |
exception | Yes | Supported as part of C++11. |
stdexcept | Yes | - |
system_error | Yes | - |
cerrno | Yes | - |
contract | No | Header is not provided, C++20 is not yet supported. |

## Strings Library
Header | Supported | Comments |
:---:|:---:|:---|
cctype | Partial | Only basic support for C/POSIX locale. |
charconv | No | C++17 is not yet supported. |
cuchar | No | Header is not provided. |
cwchar | Partial | Only basic support for C/POSIX locale. <br> **Unsupported functions:** <br> - All I/O (e.g. swprintf()). <br> - All multi-byte & wide string conversions (e.g. mbrtowc()). |
cwctype | Partial | Only basic support for C/POSIX locale. |
cstring | Partial | Only basic support for C/POSIX locale. |
string | Yes | Supported as part of C++11. |
string_view | No | C++17 is not yet supported. |

## Containers Library
Header | Supported | Comments |
:---:|:---:|:---|
array | Yes | Supported as part of C++11. |
deque | Yes | - |
forward_list | Yes | - |
list | Yes | - |
map | Yes | Supported as part of C++11. |
queue | Yes | - |
set | Yes | Supported as part of C++11. |
stack | Yes | - |
unordered_map | Yes | Supported as part of C++11. |
unordered_set | Yes | Supported as part of C++11. |
vector | Yes | - |
span | No | C++20 is not yet supported. |

## Iterators Library
Header | Supported | Comments |
:---:|:---:|:---|
iterator | Yes | - |

## Ranges Library
Header | Supported | Comments |
:---:|:---:|:---|
ranges | No | Header is not provided, C++20 is not yet supported. |

## Algorithms Library
Header | Supported | Comments |
:---:|:---:|:---|
algorithm | Yes | Supported as part of C++11. |

## Numerics Library
Header | Supported | Comments |
:---:|:---:|:---|
bit | No | Header is not provided, C++20 is not yet supported. |
cfenv | Yes | Supported as part of C++11. |
cmath | Partial | **Unsupported functions:** acosh(), asinh(), fmal(), lgamma(), lgammaf(), sinh(), sinhl(), tgamma(). |
complex | Yes | - |
numeric | Yes | Supported as part of C++11. |
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
regex | No | - |

## Atomic Operations Library
Header | Supported | Comments |
:---:|:---:|:---|
atomic | Yes | Supported as part of C++11. |

## Thread Support Library
Header | Supported | Comments |
:---:|:---:|:---|
condition_variable | Partial | Supported as part of C++11. Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. |
future | Partial | Supported as part of C++11. Asynchronous invocations are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. |
mutex | Partial | Supported as part of C++11. Synchronization primitives are not secure across calls to host. Threads are still scheduled by the untrusted host process and an enclave cannot rely on threads making forward progress. <br> **Unsupported classes:** timed_mutex, recursive_timed_mutex. |
shared_mutex | No | - |
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
