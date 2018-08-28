#include <dlfcn.h>
#define C(n) switch(n){case n:;}
static void f()
{
C(RTLD_LAZY)
C(RTLD_NOW)
C(RTLD_GLOBAL)
C(RTLD_LOCAL)

{int(*p)(void*) = dlclose;}
{char*(*p)(void) = dlerror;}
{void*(*p)(const char*,int) = dlopen;}
{void*(*p)(void*restrict,const char*restrict) = dlsym;}
}
