#include <fenv.h>
#include <math.h>
#include <float.h>

#undef RN
#undef RZ
#undef RD
#undef RU
#define RN FE_TONEAREST
#define RZ FE_TOWARDZERO
#define RD FE_DOWNWARD
#define RU FE_UPWARD

#undef INEXACT
#undef INVALID
#undef DIVBYZERO
#undef UNDERFLOW
#undef OVERFLOW
#define INEXACT FE_INEXACT
#define INVALID FE_INVALID
#define DIVBYZERO FE_DIVBYZERO
#define UNDERFLOW FE_UNDERFLOW
#define OVERFLOW FE_OVERFLOW

#undef inf
#undef nan
#define inf INFINITY
#define nan NAN

struct t {
	int type;
	int r;
	long double x;
	long double x2;
	long double x3;
	long long i;
	long double y;
	long double y2;
	float dy;
	float dy2;
	int e;
};

char *skipstr(char *, char *);
int splitstr(char **, int, char *, char *);
char *dropcomm(char *);

char *estr(int);
char *rstr(int);
int rconv(int *, char *);
int econv(int *, char *);

int eulp(double);
int eulpf(float);
int eulpl(long double);
double ulperr(double y, double ycr, double dy);

void setupfenv(int);
int getexcept(void);

#define T(f,x) int mp##f(struct t *);
#include "functions.h"
#undef T

