#ifndef __ELIBC_FENV_H
#define __ELIBC_FENV_H

#include <features.h>
#include <bits/alltypes.h>
#include <bits/fenv.h>

__ELIBC_BEGIN

int feclearexcept(int);

int fegetexceptflag(fexcept_t *, int);

int feraiseexcept(int);

int fesetexceptflag(const fexcept_t *, int);

int fetestexcept(int);

int fegetround(void);

int fesetround(int);

int fegetenv(fenv_t *);

int feholdexcept(fenv_t *);

int fesetenv(const fenv_t *);

int feupdateenv(const fenv_t *);

int __fesetround(int r);

__ELIBC_END

#endif /* __ELIBC_FENV_H */
