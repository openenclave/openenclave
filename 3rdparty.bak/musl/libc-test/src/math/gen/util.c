#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "gen.h"

int eulpf(float x)
{
	union { float f; uint32_t i; } u = { x };
	int e = u.i>>23 & 0xff;

	if (!e)
		e++;
	return e - 0x7f - 23;
}

int eulp(double x)
{
	union { double f; uint64_t i; } u = { x };
	int e = u.i>>52 & 0x7ff;

	if (!e)
		e++;
	return e - 0x3ff - 52;
}

int eulpl(long double x)
{
#if LDBL_MANT_DIG == 53
	return eulp(x);
#elif LDBL_MANT_DIG == 64
	union { long double f; struct {uint64_t m; uint16_t e; uint16_t pad;} i; } u = { x };
	int e = u.i.e & 0x7fff;

	if (!e)
		e++;
	return e - 0x3fff - 63;
#else
	// TODO
	return 0;
#endif
}

double ulperr(double y, double ycr, double dy)
{
	return dy + scalbn(ycr - y, -eulp(ycr));
}

char *skipstr(char *buf, char *sep)
{
	while (*buf && strchr(sep, *buf))
		buf++;
	return buf;
}

int splitstr(char **a, int n, char *buf, char *sep)
{
	int i, j;

	for (i = j = 0; j < n; j++) {
		for (; buf[i] && strchr(sep, buf[i]); i++)
				buf[i] = 0;
		a[j] = buf + i;
		if (buf[i] == 0)
			break;
		for (i++; buf[i] && !strchr(sep, buf[i]); i++);
	}
	return j;
}

char *dropcomm(char *buf)
{
	char *p = buf;

	for (; *p; p++)
		if ((*p == '/' && p[1] == '/') || *p == '#') {
			*p = 0;
			break;
		}
	return buf;
}

#define length(a) (sizeof(a)/sizeof(*a))
#define flag(x) {x, #x}
static struct {
	int flag;
	char *s;
} eflags[] = {
	flag(INEXACT),
	flag(INVALID),
	flag(DIVBYZERO),
	flag(UNDERFLOW),
	flag(OVERFLOW)
};

char *estr(int f)
{
	static char buf[256];
	char *p = buf;
	int i, all = 0;

	for (i = 0; i < length(eflags); i++)
		if (f & eflags[i].flag) {
			p += sprintf(p, "%s%s", all ? "|" : "", eflags[i].s);
			all |= eflags[i].flag;
		}
	if (all != f) {
		p += sprintf(p, "%s%d", all ? "|" : "", f & ~all);
		all = f;
	}
	p += sprintf(p, "%s", all ? "" : "0");
	return buf;
}

int econv(int *f, char *s)
{
	char *a[16];
	char *e;
	int i,j,k,n;

	*f = 0;
	n = splitstr(a, length(a), s, "|");
	for (i = 0; i < n; i++) {
		for (j = 0; j < length(eflags); j++)
			if (strcmp(a[i], eflags[j].s) == 0) {
				*f |= eflags[j].flag;
				break;
			}
		if (j == length(eflags)) {
			k = strtol(a[i], &e, 0);
			if (*e)
				return -1;
			*f |= k;
		}
	}
	return 0;
}

char *rstr(int r)
{
	switch (r) {
	case RN: return "RN";
	case RZ: return "RZ";
	case RU: return "RU";
	case RD: return "RD";
	}
	return "R?";
}

int rconv(int *r, char *s)
{
	if (strcmp(s, "RN") == 0)
		*r = RN;
	else if (strcmp(s, "RZ") == 0)
		*r = RZ;
	else if (strcmp(s, "RD") == 0)
		*r = RD;
	else if (strcmp(s, "RU") == 0)
		*r = RU;
	else
		return -1;
	return 0;
}

void setupfenv(int r)
{
	fesetround(r);
	feclearexcept(FE_ALL_EXCEPT);
}

int getexcept(void)
{
	return fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);
}

