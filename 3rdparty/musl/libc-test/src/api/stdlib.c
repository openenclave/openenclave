#include <stdlib.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
#define I(t,e) {t x[sizeof(t)==sizeof(e)] = {e};}
static void f()
{
C(EXIT_FAILURE)
C(EXIT_SUCCESS)
C(RAND_MAX)
I(size_t,MB_CUR_MAX)
{void *x=NULL;}
T(div_t)
T(ldiv_t)
T(lldiv_t)
T(size_t)
T(wchar_t)
#ifdef _POSIX_C_SOURCE
C(WEXITSTATUS(0))
C(WIFEXITED(0))
C(WIFSIGNALED(0))
C(WIFSTOPPED(0))
C(WNOHANG)
C(WSTOPSIG(0))
C(WTERMSIG(0))
C(WUNTRACED)
#endif
{void(*p)(int) = _Exit;}
{void(*p)(void) = abort;}
{int(*p)(int) = abs;}
{int(*p)(void(*)(void)) = atexit;}
{double(*p)(const char*) = atof;}
{int(*p)(const char*) = atoi;}
{long(*p)(const char*) = atol;}
{long long(*p)(const char*) = atoll;}
{void*(*p)(const void*,const void*,size_t,size_t,int(*)(const void*,const void*)) = bsearch;}
{void*(*p)(size_t,size_t) = calloc;}
{div_t(*p)(int,int) = div;}
{void(*p)(int) = exit;}
{void(*p)(void*) = free;}
{char*(*p)(const char*) = getenv;}
{int(*p)(char**,char*const*,char**) = getsubopt;}
{long(*p)(long) = labs;}
{ldiv_t(*p)(long,long) = ldiv;}
{long long(*p)(long long) = llabs;}
{lldiv_t(*p)(long long,long long) = lldiv;}
{void*(*p)(size_t) = malloc;}
{int(*p)(const char*,size_t) = mblen;}
{size_t(*p)(wchar_t*restrict,const char*restrict,size_t) = mbstowcs;}
{int(*p)(wchar_t*restrict,const char*restrict,size_t) = mbtowc;}
{int(*p)(void**,size_t,size_t) = posix_memalign;}
{void(*p)(void*,size_t,size_t,int(*)(const void*,const void*)) = qsort;}
{int(*p)(void) = rand;}
{void*(*p)(void*,size_t) = realloc;}
{void(*p)(unsigned) = srand;}
{double(*p)(const char*restrict,char**restrict) = strtod;}
{float(*p)(const char*restrict,char**restrict) = strtof;}
{long(*p)(const char*restrict,char**restrict,int) = strtol;}
{long double(*p)(const char*restrict,char**restrict) = strtold;}
{long long(*p)(const char*restrict,char**restrict,int) = strtoll;}
{unsigned long(*p)(const char*restrict,char**restrict,int) = strtoul;}
{unsigned long long(*p)(const char*restrict,char**restrict,int) = strtoull;}
{int(*p)(const char*) = system;}
{size_t(*p)(char*restrict,const wchar_t*restrict,size_t) = wcstombs;}
{int(*p)(char*,wchar_t) = wctomb;}
#ifdef _POSIX_C_SOURCE
{char*(*p)(char*) = mkdtemp;}
{int(*p)(char*) = mkstemp;}
{int(*p)(const char*,const char*,int) = setenv;}
{int(*p)(const char*) = unsetenv;}
#endif
#ifdef _XOPEN_SOURCE
{long(*p)(const char*) = a64l;}
{double(*p)(void) = drand48;}
{double(*p)(unsigned short[]) = erand48;}
{int(*p)(int) = grantpt;}
{char*(*p)(unsigned,char*,size_t) = initstate;}
{long(*p)(unsigned short[]) = jrand48;}
{char*(*p)(long) = l64a;}
{void(*p)(unsigned short[]) = lcong48;}
{long(*p)(void) = lrand48;}
{long(*p)(void) = mrand48;}
{long(*p)(unsigned short[]) = nrand48;}
{char*(*p)(int) = ptsname;}
{int(*p)(char*) = putenv;}
{long(*p)(void) = random;}
{char*(*p)(const char*restrict,char*restrict) = realpath;}
{unsigned short*(*p)(unsigned short[]) = seed48;}
{void(*p)(const char*) = setkey;}
{char*(*p)(char*) = setstate;}
{void(*p)(long) = srand48;}
{void(*p)(unsigned) = srandom;}
{int(*p)(int) = unlockpt;}
#endif
}

#ifdef _XOPEN_SOURCE
#include <fcntl.h>
static void g()
{
{int(*p)(int) = posix_openpt;}
}
#endif

