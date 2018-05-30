# Open Enclave Support for libcxx

Header | Supported? | Comments |
:---:|:---:|:---:|
algorithm | Partial | Supported functions: find(), find_first_of(), count(), mismatch(), equal(), search(), copy(), move(), transform(), replace(), fill(), generate(), remove(), unique(), reverse(), min(), max(), a(), b(), reset(), param(), sort(), lower_bound() |
any | Partial | Unsupported function: make_any() |
array | Yes | - |
bitset | Partial | Supported functions: base(), bitset(), set(), reset(), to_string(), test() |
cassert | Yes | - |
cctype | Partial | Unsupported functions: isalnum(), isaplha(), iscntrl(), isgraph(), isspace(), isblank(), isprint(), ispunct() |
cfenv | No | - |
charconv | No | - |
chrono | Yes | - |
clocale | Partial | Only basic support for C/POSIX locale |
cmath | Partial | Supported functions: abs(), nan(), exp(), log(), sin(), tan(), asin(), erf(), trunc(), round(), rint(), modf() |
codecvt | Yes | - |
compare | No | - |
complex | Yes | - |
condtion_variable | Yes | - |
csignal | Yes | - |
cstdarg | Partial | Supported function: va_list() |
cstddef | Yes | - |
cstdint | Yes | - |
cstdio | Partial | Unsupported functions: vscanf(), fputs() |
cstdlib | Partial | Unsupported functions: at_quick_exit(), quick_exit(), aligned_alloca() |
cstring | Partial | Unsupported functions: strcpy(), strcat(), strncat(), strchr(), strcspn(), strpbrk(), strrchr(), strspn() |
ctime | Yes | - |
cwchar | Partial | Unsupported functions: wscanff(), wscanfs(), wscanf(), wprintff(), wprintfs(), wprintf(), fputwcputwc(), fgetwcgetwc() |
cwctype | Yes | - |
cuchar | No | - |
execution | Partial | Unsupported functions: is_execution_policy(), sequenced_policy(), parallel_policy(), parallel_unsequenced_policy(), par_unseq() |
exception | Partial | Unsupported functions: throw_with_nested(), rethrow_if_nested() |
functional | No | - |
future | Yes | - |
fstream | Partial | Unsupported functions: is_open(), basic_ifstream(), basic_filebuf() |
initializer_list | Yes | - |
ios | Partial | Unsupported functions: nounitbuf(), nouppercase(), noshowpos(), noshowpoint(), noshowbase(), noboolalpha() |
istream | Yes | - |
iterator | Partial | Unsupported functions: make_reverse_iterator(), make_move_iterator(), front_inserter(), back_inserter(), inserter(), begincbegin(),  endcend(), rbegincrbegin(), rendcrend() |
map | Partial | Unsupported function: multimap() |
memory_resource | No | - |
new | Partial | Unsupported function: launder() |
numeric | Partial | Unsupported functions: accumulate(), transform_reduce(), inner_product(), adjacent_difference(), partial_sum(), inclusive_scan(), exclusive_scan(), transform_inclusive_scan(), transform_exclusive_scan() |
mutex | Partial | Unsupported function: try_lock_until() |
optional | Yes | - |
ostream | Partial | Unsupported function: endl() |
queue | Yes | - |
random | Partial | Unsupported functions: probablities(), generate_canonical() |
ratio | Yes | - |
regex | No | - |
set | Partial | Unsupported function: multiset() |
sstream | Partial | Unsupported functions: basic_ostringstream(), basic_stringstream(), basic_stringbuf() |
stddef | Yes |  - |
streambuf | Yes | - |
syncstream | No | - |
system error | Yes | - |
thread | Yes | Unsupported function: sleep_until() |
tuple | Partial | Supported function: pair() |
typeinfo | No | - |
type_traits | Partial | Supported functions: decltype(), move(), size_of() |
unordered_map | Partial | Unsupported functions: unordered_map(), unordered_multimap() |
unordered_set | Partial | Unsupported functions: unordered_set(), unordered_multiset() |
utility | Partial | Unsupported function : make_pair() |
varriant | Partial | Unsupported function: visit(), holds_alternative(), get_if() |
vector | Yes | - |
version | No | - |
