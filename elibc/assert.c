#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

__NORETURN void __assert_fail(
    const char *expr,
    const char *file,
    unsigned int line,
    const char *function)
{
    fprintf_u(stderr, 
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, function, line);
    abort();
}
