#include <stdarg.h>
#define T(t) (t*)0;
static void f()
{
T(va_list)
#ifndef va_start
#error no va_start
#endif
#ifndef va_arg
#error no va_arg
#endif
#ifndef va_end
#error no va_end
#endif
#ifndef va_copy
#error no va_copy
#endif
}
