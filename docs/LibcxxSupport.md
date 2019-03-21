# Open Enclave Support for libcxx

Header | Supported | Comments |
:---:|:---:|:---|
algorithm | Partial | **Supported functions:** find(), find_first_of(), count(), mismatch(), equal(), search(), copy(), move(), transform(), replace(), fill(), generate(), remove(), unique(), reverse(), min(), max(), sort(), lower_bound() |
array | Yes | - |
bitset | Partial | **Supported functions:** base(), bitset(), reset(), set(), to_string(), test() |
cassert | Yes | - |
cctype | Partial | **Unsupported functions:** isalnum(), isaplha(), iscntrl(), isgraph(), isspace(), isblank(), isprint(), ispunct() |
cfenv | No | - |
charconv | No | - |
chrono | Partial | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported classes:** system_clock, treat_as_floating_point, duration_values |
clocale | Partial | Only basic support for C/POSIX locale |
cmath | Partial | **Supported functions:** abs(), nan(), exp(), log(), sin(), tan(), asin(), erf(), trunc(), round(), rint(), modf() |
codecvt | Yes | - |
compare | No | - |
complex | Yes | - |
condition_variable | Yes | - |
csetjmp | Yes | - |
csignal | Yes | - |
cstdarg | No | - |
cstddef | Yes | - |
cstdint | Yes | - |
cstdio | Partial | All I/O functions implicitly call out to untrusted host. <br> **Unsupported functions:** ferror(), vscanf() |
cstdlib | Partial | **Unsupported functions:** at_quick_exit(), quick_exit() |
cstring | Partial | **Unsupported functions:** strcpy(), strcat(), strncat(), strchr(), strcspn(), strspn() |
ctime | Yes | All time functions implicitly call out to untrusted host for time values. The resulting time values should not be used for security purposes. <br> **Supported functions:** time(), gettimeofday(), clock_gettime(), nanosleep(). _Please note that clock_gettime() only supports CLOCK_REALTIME_ |
cwchar | Partial | **Unsupported functions:** wscanf(), wprintf() |
cwctype | Yes | - |
cuchar | No | - |
exception | Partial | **Unsupported functions:** throw_with_nested(), rethrow_if_nested() |
functional | No | - |
future | Yes | - |
fstream | Yes | All I/O functions implicitly call out to untrusted host. |
initializer_list | Yes | - |
iomanip | Partial | **Unsupported functions:** get_money(), put_money(), get_time(), put_time() |
ios | Partial | **Unsupported functions:** nounitbuf(), nouppercase(), noshowpos(), noshowpoint(), noshowbase(), noboolalpha() |
istream | Yes | - |
iterator | Partial | **Unsupported functions:** make_reverse_iterator(), make_move_iterator(), front_inserter(), back_inserter(), inserter(), begin(), cbegin(), rbegin(), crbegin() |
new | Yes | - |
numeric | Partial | **Unsupported functions:** accumulate(), inner_product(), adjacent_difference(), partial_sum() |
mutex | Yes | - |
optional | Yes | - |
ostream | Partial | **Unsupported function:** endl() |
queue | Yes | - |
random | Partial | **Unsupported functions:** generate_canonical() |
ratio | Yes | - |
regex | No | - |
set | Yes | - |
sstream | Yes | - |
stddef | Yes |  - |
streambuf | Yes | - |
system_error | Yes | - |
thread | No | - |
tuple | Partial | **Supported function:** tie() |
typeindex | Yes | - |
typeinfo | No | - |
type_traits | No | - |
unordered_map | Yes | - |
unordered_set | Yes | - |
utility | Partial | **Unsupported function:** make_pair() |
vector | Yes | - |
version | No | - |
