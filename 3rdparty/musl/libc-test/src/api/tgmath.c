#include <tgmath.h>
static void f()
{
double x=0, y=0, z=0;
int i;
#ifdef acos
{double r = acos(x);}
#else
#error no acos(x)
#endif
#ifdef acosh
{double r = acosh(x);}
#else
#error no acosh(x)
#endif
#ifdef asin
{double r = asin(x);}
#else
#error no asin(x)
#endif
#ifdef asinh
{double r = asinh(x);}
#else
#error no asinh(x)
#endif
#ifdef atan
{double r = atan(x);}
#else
#error no atan(x)
#endif
#ifdef atan2
{double r = atan2(x,y);}
#else
#error no atan2(x,y)
#endif
#ifdef atanh
{double r = atanh(x);}
#else
#error no atanh(x)
#endif
#ifdef carg
{double r = carg(x);}
#else
#error no carg(x)
#endif
#ifdef cbrt
{double r = cbrt(x);}
#else
#error no cbrt(x)
#endif
#ifdef ceil
{double r = ceil(x);}
#else
#error no ceil(x)
#endif
#ifdef cimag
{double r = cimag(x);}
#else
#error no cimag(x)
#endif
#ifdef conj
{double r = conj(x);}
#else
#error no conj(x)
#endif
#ifdef copysign
{double r = copysign(x,y);}
#else
#error no copysign(x,y)
#endif
#ifdef cos
{double r = cos(x);}
#else
#error no cos(x)
#endif
#ifdef cosh
{double r = cosh(x);}
#else
#error no cosh(x)
#endif
#ifdef cproj
{double r = cproj(x);}
#else
#error no cproj(x)
#endif
#ifdef creal
{double r = creal(x);}
#else
#error no creal(x)
#endif
#ifdef erf
{double r = erf(x);}
#else
#error no erf(x)
#endif
#ifdef erfc
{double r = erfc(x);}
#else
#error no erfc(x)
#endif
#ifdef exp
{double r = exp(x);}
#else
#error no exp(x)
#endif
#ifdef exp2
{double r = exp2(x);}
#else
#error no exp2(x)
#endif
#ifdef expm1
{double r = expm1(x);}
#else
#error no expm1(x)
#endif
#ifdef fabs
{double r = fabs(x);}
#else
#error no fabs(x)
#endif
#ifdef fdim
{double r = fdim(x,y);}
#else
#error no fdim(x,y)
#endif
#ifdef floor
{double r = floor(x);}
#else
#error no floor(x)
#endif
#ifdef fma
{double r = fma(x,y,z);}
#else
#error no fma(x,y,z)
#endif
#ifdef fmax
{double r = fmax(x,y);}
#else
#error no fmax(x,y)
#endif
#ifdef fmin
{double r = fmin(x,y);}
#else
#error no fmin(x,y)
#endif
#ifdef fmod
{double r = fmod(x,y);}
#else
#error no fmod(x,y)
#endif
#ifdef frexp
{double r = frexp(x,&i);}
#else
#error no frexp(x,y)
#endif
#ifdef hypot
{double r = hypot(x,y);}
#else
#error no hypot(x,y)
#endif
#ifdef ilogb
{double r = ilogb(x);}
#else
#error no ilogb(x)
#endif
#ifdef ldexp
{double r = ldexp(x,y);}
#else
#error no ldexp(x,y)
#endif
#ifdef lgamma
{double r = lgamma(x);}
#else
#error no lgamma(x)
#endif
#ifdef llrint
{double r = llrint(x);}
#else
#error no llrint(x)
#endif
#ifdef llround
{double r = llround(x);}
#else
#error no llround(x)
#endif
#ifdef log
{double r = log(x);}
#else
#error no log(x)
#endif
#ifdef log10
{double r = log10(x);}
#else
#error no log10(x)
#endif
#ifdef log1p
{double r = log1p(x);}
#else
#error no log1p(x)
#endif
#ifdef log2
{double r = log2(x);}
#else
#error no log2(x)
#endif
#ifdef logb
{double r = logb(x);}
#else
#error no logb(x)
#endif
#ifdef lrint
{double r = lrint(x);}
#else
#error no lrint(x)
#endif
#ifdef lround
{double r = lround(x);}
#else
#error no lround(x)
#endif
#ifdef nearbyint
{double r = nearbyint(x);}
#else
#error no nearbyint(x)
#endif
#ifdef nextafter
{double r = nextafter(x,y);}
#else
#error no nextafter(x,y)
#endif
#ifdef nexttoward
{double r = nexttoward(x,y);}
#else
#error no nexttoward(x,y)
#endif
#ifdef pow
{double r = pow(x,y);}
#else
#error no pow(x,y)
#endif
#ifdef remainder
{double r = remainder(x,y);}
#else
#error no remainder(x,y)
#endif
#ifdef remquo
{double r = remquo(x,y,&i);}
#else
#error no remquo(x,y,z)
#endif
#ifdef rint
{double r = rint(x);}
#else
#error no rint(x)
#endif
#ifdef round
{double r = round(x);}
#else
#error no round(x)
#endif
#ifdef scalbln
{double r = scalbln(x,y);}
#else
#error no scalbln(x,y)
#endif
#ifdef scalbn
{double r = scalbn(x,y);}
#else
#error no scalbn(x,y)
#endif
#ifdef sin
{double r = sin(x);}
#else
#error no sin(x)
#endif
#ifdef sinh
{double r = sinh(x);}
#else
#error no sinh(x)
#endif
#ifdef sqrt
{double r = sqrt(x);}
#else
#error no sqrt(x)
#endif
#ifdef tan
{double r = tan(x);}
#else
#error no tan(x)
#endif
#ifdef tanh
{double r = tanh(x);}
#else
#error no tanh(x)
#endif
#ifdef tgamma
{double r = tgamma(x);}
#else
#error no tgamma(x)
#endif
#ifdef trunc
{double r = trunc(x);}
#else
#error no trunc(x)
#endif
}

