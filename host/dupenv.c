#include "dupenv.h"
#include <string.h>
#include <stdlib.h>

char* Dupenv(
    const char* name)
{
#if defined(__linux__)

    const char* s = getenv(name);

    if (!s)
        return NULL;

    return strdup(s);

#elif defined(_WIN32)

    char* p = NULL;
    size_t n;

    if (_dupenv_s(&p, &n, name) != 0)
        return NULL;

    return p;

#endif
}
