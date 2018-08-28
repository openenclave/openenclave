#include <fenv.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(fenv_t)
T(fexcept_t)
//FE_DIVBYZERO
//FE_INEXACT
//FE_INVALID
//FE_OVERFLOW
//FE_UNDERFLOW
C(FE_ALL_EXCEPT)
//FE_DOWNWARD
//FE_TONEAREST
//FE_TOWARDZERO
//FE_UPWARD
{const fenv_t *c = FE_DFL_ENV;}
{int(*p)(int) = feclearexcept;}
{int(*p)(fenv_t*) = fegetenv;}
{int(*p)(fexcept_t*,int) = fegetexceptflag;}
{int(*p)(void) = fegetround;}
{int(*p)(fenv_t*) = feholdexcept;}
{int(*p)(int) = feraiseexcept;}
{int(*p)(const fenv_t*) = fesetenv;}
{int(*p)(const fexcept_t*,int) = fesetexceptflag;}
{int(*p)(int) = fesetround;}
{int(*p)(int) = fetestexcept;}
{int(*p)(const fenv_t*) = feupdateenv;}
}
