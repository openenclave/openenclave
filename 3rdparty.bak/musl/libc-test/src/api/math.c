#include <math.h>
#define T(t) (t*)0;
#define C(n) switch(n){case n:;}
#define I(t,e) {t x[sizeof(t)==sizeof(e)] = {e};}
#define D(n) {double d = n;}
static void f()
{
T(float_t)
T(double_t)
I(int,fpclassify(.0))
I(int,isfinite(.0))
I(int,isgreater(.0,.0))
I(int,isgreaterequal(.0,.0))
I(int,isinf(.0))
I(int,isless(.0,.0))
I(int,islessequal(.0,.0))
I(int,islessgreater(.0,.0))
I(int,isnan(.0))
I(int,isnormal(.0))
I(int,isunordered(.0,.0))
I(int,signbit(.0))
#ifdef _XOPEN_SOURCE
I(int,signgam)
D(M_E)
D(M_LOG2E)
D(M_LOG10E)
D(M_LN2)
D(M_LN10)
D(M_PI)
D(M_PI_2)
D(M_PI_4)
D(M_1_PI)
D(M_2_PI)
D(M_2_SQRTPI)
D(M_SQRT2)
D(M_SQRT1_2)
D(MAXFLOAT)
#endif
D(HUGE_VAL)
D(HUGE_VALF)
D(HUGE_VALL)
D(INFINITY)
D(NAN)
C(FP_INFINITE)
C(FP_NAN)
C(FP_NORMAL)
C(FP_SUBNORMAL)
C(FP_ZERO)
C(FP_ILOGB0)
C(FP_ILOGBNAN)
C(MATH_ERRNO)
C(MATH_ERREXCEPT)
C(math_errhandling)
{double(*p)(double) = acos;}
{float(*p)(float) = acosf;}
{double(*p)(double) = acosh;}
{float(*p)(float) = acoshf;}
{long double(*p)(long double) = acoshl;}
{long double(*p)(long double) = acosl;}
{double(*p)(double) = asin;}
{float(*p)(float) = asinf;}
{double(*p)(double) = asinh;}
{float(*p)(float) = asinhf;}
{long double(*p)(long double) = asinhl;}
{long double(*p)(long double) = asinl;}
{double(*p)(double) = atan;}
{double(*p)(double,double) = atan2;}
{float(*p)(float,float) = atan2f;}
{long double(*p)(long double,long double) = atan2l;}
{float(*p)(float) = atanf;}
{double(*p)(double) = atanh;}
{float(*p)(float) = atanhf;}
{long double(*p)(long double) = atanhl;}
{long double(*p)(long double) = atanl;}
{double(*p)(double) = cbrt;}
{float(*p)(float) = cbrtf;}
{long double(*p)(long double) = cbrtl;}
{double(*p)(double) = ceil;}
{float(*p)(float) = ceilf;}
{long double(*p)(long double) = ceill;}
{double(*p)(double,double) = copysign;}
{float(*p)(float,float) = copysignf;}
{long double(*p)(long double,long double) = copysignl;}
{double(*p)(double) = cos;}
{float(*p)(float) = cosf;}
{double(*p)(double) = cosh;}
{float(*p)(float) = coshf;}
{long double(*p)(long double) = coshl;}
{long double(*p)(long double) = cosl;}
{double(*p)(double) = erf;}
{double(*p)(double) = erfc;}
{float(*p)(float) = erfcf;}
{long double(*p)(long double) = erfcl;}
{float(*p)(float) = erff;}
{long double(*p)(long double) = erfl;}
{double(*p)(double) = exp;}
{double(*p)(double) = exp2;}
{float(*p)(float) = exp2f;}
{long double(*p)(long double) = exp2l;}
{float(*p)(float) = expf;}
{long double(*p)(long double) = expl;}
{double(*p)(double) = expm1;}
{float(*p)(float) = expm1f;}
{long double(*p)(long double) = expm1l;}
{double(*p)(double) = fabs;}
{float(*p)(float) = fabsf;}
{long double(*p)(long double) = fabsl;}
{double(*p)(double,double) = fdim;}
{float(*p)(float,float) = fdimf;}
{long double(*p)(long double,long double) = fdiml;}
{double(*p)(double) = floor;}
{float(*p)(float) = floorf;}
{long double(*p)(long double) = floorl;}
{double(*p)(double,double,double) = fma;}
{float(*p)(float,float,float) = fmaf;}
{long double(*p)(long double,long double,long double) = fmal;}
{double(*p)(double,double) = fmax;}
{float(*p)(float,float) = fmaxf;}
{long double(*p)(long double,long double) = fmaxl;}
{double(*p)(double,double) = fmin;}
{float(*p)(float,float) = fminf;}
{long double(*p)(long double,long double) = fminl;}
{double(*p)(double,double) = fmod;}
{float(*p)(float,float) = fmodf;}
{long double(*p)(long double,long double) = fmodl;}
{double(*p)(double,int*) = frexp;}
{float(*p)(float,int*) = frexpf;}
{long double(*p)(long double,int*) = frexpl;}
{double(*p)(double,double) = hypot;}
{float(*p)(float,float) = hypotf;}
{long double(*p)(long double,long double) = hypotl;}
{int(*p)(double) = ilogb;}
{int(*p)(float) = ilogbf;}
{int(*p)(long double) = ilogbl;}
#ifdef _XOPEN_SOURCE
{double(*p)(double) = j0;}
{double(*p)(double) = j1;}
{double(*p)(int,double) = jn;}
#endif
{double(*p)(double,int) = ldexp;}
{float(*p)(float,int) = ldexpf;}
{long double(*p)(long double,int) = ldexpl;}
{double(*p)(double) = lgamma;}
{float(*p)(float) = lgammaf;}
{long double(*p)(long double) = lgammal;}
{long long(*p)(double) = llrint;}
{long long(*p)(float) = llrintf;}
{long long(*p)(long double) = llrintl;}
{long long(*p)(double) = llround;}
{long long(*p)(float) = llroundf;}
{long long(*p)(long double) = llroundl;}
{double(*p)(double) = log;}
{double(*p)(double) = log10;}
{float(*p)(float) = log10f;}
{long double(*p)(long double) = log10l;}
{double(*p)(double) = log1p;}
{float(*p)(float) = log1pf;}
{long double(*p)(long double) = log1pl;}
{double(*p)(double) = log2;}
{float(*p)(float) = log2f;}
{long double(*p)(long double) = log2l;}
{double(*p)(double) = logb;}
{float(*p)(float) = logbf;}
{long double(*p)(long double) = logbl;}
{float(*p)(float) = logf;}
{long double(*p)(long double) = logl;}
{long(*p)(double) = lrint;}
{long(*p)(float) = lrintf;}
{long(*p)(long double) = lrintl;}
{long(*p)(double) = lround;}
{long(*p)(float) = lroundf;}
{long(*p)(long double) = lroundl;}
{double(*p)(double,double*) = modf;}
{float(*p)(float,float*) = modff;}
{long double(*p)(long double,long double*) = modfl;}
{double(*p)(const char*) = nan;}
{float(*p)(const char*) = nanf;}
{long double(*p)(const char*) = nanl;}
{double(*p)(double) = nearbyint;}
{float(*p)(float) = nearbyintf;}
{long double(*p)(long double) = nearbyintl;}
{double(*p)(double,double) = nextafter;}
{float(*p)(float,float) = nextafterf;}
{long double(*p)(long double,long double) = nextafterl;}
{double(*p)(double,long double) = nexttoward;}
{float(*p)(float,long double) = nexttowardf;}
{long double(*p)(long double,long double) = nexttowardl;}
{double(*p)(double,double) = pow;}
{float(*p)(float,float) = powf;}
{long double(*p)(long double,long double) = powl;}
{double(*p)(double,double) = remainder;}
{float(*p)(float,float) = remainderf;}
{long double(*p)(long double,long double) = remainderl;}
{double(*p)(double,double,int*) = remquo;}
{float(*p)(float,float,int*) = remquof;}
{long double(*p)(long double,long double,int*) = remquol;}
{double(*p)(double) = rint;}
{float(*p)(float) = rintf;}
{long double(*p)(long double) = rintl;}
{double(*p)(double) = round;}
{float(*p)(float) = roundf;}
{long double(*p)(long double) = roundl;}
{double(*p)(double,long) = scalbln;}
{float(*p)(float,long) = scalblnf;}
{long double(*p)(long double,long) = scalblnl;}
{double(*p)(double,int) = scalbn;}
{float(*p)(float,int) = scalbnf;}
{long double(*p)(long double,int) = scalbnl;}
{double(*p)(double) = sin;}
{float(*p)(float) = sinf;}
{double(*p)(double) = sinh;}
{float(*p)(float) = sinhf;}
{long double(*p)(long double) = sinhl;}
{long double(*p)(long double) = sinl;}
{double(*p)(double) = sqrt;}
{float(*p)(float) = sqrtf;}
{long double(*p)(long double) = sqrtl;}
{double(*p)(double) = tan;}
{float(*p)(float) = tanf;}
{double(*p)(double) = tanh;}
{float(*p)(float) = tanhf;}
{long double(*p)(long double) = tanhl;}
{long double(*p)(long double) = tanl;}
{double(*p)(double) = tgamma;}
{float(*p)(float) = tgammaf;}
{long double(*p)(long double) = tgammal;}
{double(*p)(double) = trunc;}
{float(*p)(float) = truncf;}
{long double(*p)(long double) = truncl;}
#ifdef _XOPEN_SOURCE
{double(*p)(double) = y0;}
{double(*p)(double) = y1;}
{double(*p)(int,double) = yn;}
#endif
}
