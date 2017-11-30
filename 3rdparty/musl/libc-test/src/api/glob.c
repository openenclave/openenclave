#include <glob.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(glob_t)
T(size_t)
{
glob_t x;
F(size_t, gl_pathc)
F(char**, gl_pathv)
F(size_t, gl_offs)
}
C(GLOB_APPEND)
C(GLOB_DOOFFS)
C(GLOB_ERR)
C(GLOB_MARK)
C(GLOB_NOCHECK)
C(GLOB_NOESCAPE)
C(GLOB_NOSORT)
C(GLOB_ABORTED)
C(GLOB_NOMATCH)
C(GLOB_NOSPACE)
{int(*p)(const char*restrict,int,int(*)(const char*,int),glob_t*restrict) = glob;}
{void(*p)(glob_t*) = globfree;}
}
