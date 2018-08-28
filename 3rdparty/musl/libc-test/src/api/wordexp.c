#include <wordexp.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(size_t)
{
wordexp_t x;
F(size_t, we_wordc)
F(char **,we_wordv)
F(size_t, we_offs)
}
C(WRDE_APPEND)
C(WRDE_DOOFFS)
C(WRDE_NOCMD)
C(WRDE_REUSE)
C(WRDE_SHOWERR)
C(WRDE_UNDEF)
C(WRDE_BADCHAR)
C(WRDE_BADVAL)
C(WRDE_CMDSUB)
C(WRDE_NOSPACE)
C(WRDE_SYNTAX)
{int(*p)(const char*restrict,wordexp_t*restrict,int) = wordexp;}
{void(*p)(wordexp_t*) = wordfree;}
}
