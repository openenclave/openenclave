/*
./gen can generate testcases using an mp lib
./check can test an mp lib compared to the input

input format:
T.<rounding>.<inputs>.<outputs>.<outputerr>.<exceptflags>.
where . is a sequence of separators: " \t,(){}"
the T prefix and rounding mode are optional (default is RN),
so the following are all ok and equivalent input:

 1 2.0 0.1 INEXACT
 {RN, 1, 2.0, 0.1, INEXACT},
 T(RN, 1, 2.0, 0.1, INEXACT)

for gen only rounding and inputs are required (the rest is discarded)

gen:
	s = getline()
	x = scan(s)
	xy = mpfunc(x)
	print(xy)
check:
	s = getline()
	xy = scan(s)
	xy' = mpfunc(x)
	check(xy, xy')
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "gen.h"

static int scan(const char *fmt, struct t *t, char *buf);
static int print(const char *fmt, struct t *t, char *buf, int n);

// TODO: many output, fmt->ulp
struct fun;
static int check(struct t *want, struct t *got, struct fun *f, float ulpthres, float *abserr);

struct fun {
	char *name;
	int (*mpf)(struct t*);
	char *fmt;
} fun[] = {
#define T(f,t) {#f, mp##f, #t},
#include "functions.h"
#undef T
};

int main(int argc, char *argv[])
{
	char buf[512];
	char *p;
	int checkmode;
	int i;
	struct t t;
	struct t tread;
	struct fun *f = 0;
	double ulpthres = 1.0;
	float maxerr = 0;
	float abserr;
	struct t terr;

	p = strrchr(argv[0], '/');
	if (!p)
		p = argv[0];
	else
		p++;
	checkmode = strcmp(p, "check") == 0;
	if (argc < 2) {
		fprintf(stderr, "%s func%s\n", argv[0], checkmode ? " ulpthres" : "");
		return 1;
	}
	if (argc > 2 && checkmode) {
		ulpthres = strtod(argv[2], &p);
		if (*p) {
			fprintf(stderr, "invalid ulperr %s\n", argv[2]);
			return 1;
		}
	}
	for (i = 0; i < sizeof fun/sizeof *fun; i++)
		if (strcmp(fun[i].name, argv[1]) == 0) {
			f = fun + i;
			break;
		}
	if (f == 0) {
		fprintf(stderr, "unknown func: %s\n", argv[1]);
		return 1;
	}
	for (i = 1; fgets(buf, sizeof buf, stdin); i++) {
		dropcomm(buf);
		if (*buf == 0 || *buf == '\n')
			continue;
		memset(&t, 0, sizeof t);
		if (scan(f->fmt, &t, buf))
			fprintf(stderr, "error scan %s, line %d\n", f->name, i);
		tread = t;
		if (f->mpf(&t))
			fprintf(stderr, "error mpf %s, line %d\n", f->name, i);
		if (checkmode) {
			if (check(&tread, &t, f, ulpthres, &abserr)) {
				print(f->fmt, &tread, buf, sizeof buf);
				fputs(buf, stdout);
//				print(f->fmt, &t, buf, sizeof buf);
//				fputs(buf, stdout);
			}
			if (abserr > maxerr) {
				maxerr = abserr;
				terr = tread;
			}
		} else {
			if (print(f->fmt, &t, buf, sizeof buf))
				fprintf(stderr, "error fmt %s, line %d\n", f->name, i);
			fputs(buf, stdout);
		}
	}
	if (checkmode && maxerr) {
		printf("// maxerr: %f, ", maxerr);
		print(f->fmt, &terr, buf, sizeof buf);
		fputs(buf, stdout);
	}
	return 0;
}

static int check(struct t *want, struct t *got, struct fun *f, float ulpthres, float *abserr)
{
	int err = 0;
	int m = INEXACT|UNDERFLOW; // TODO: dont check inexact and underflow for now

	if ((got->e|m) != (want->e|m)) {
		fprintf(stdout, "//%s %s(%La,%La)==%La except: want %s",
			rstr(want->r), f->name, want->x, want->x2, want->y, estr(want->e));
		fprintf(stdout, " got %s\n", estr(got->e));
		err++;
	}
	if (isnan(got->y) && isnan(want->y))
		return err;
	if (got->y != want->y || signbit(got->y) != signbit(want->y)) {
		char *p;
		int n;
		float d;

		p = strchr(f->fmt, '_');
		if (!p)
			return -1;
		p++;
		if (*p == 'd')
			n = eulp(want->y);
		else if (*p == 'f')
			n = eulpf(want->y);
		else if (*p == 'l')
			n = eulpl(want->y);
		else
			return -1;

		d = scalbnl(got->y - want->y, -n);
		*abserr = fabsf(d + want->dy);
		if (*abserr <= ulpthres)
			return err;
		fprintf(stdout, "//%s %s(%La,%La) want %La got %La ulperr %.3f = %a + %a\n",
			rstr(want->r), f->name, want->x, want->x2, want->y, got->y, d + want->dy, d, want->dy);
		err++;
	}
	return err;
}

// scan discards suffixes, this may cause rounding issues (eg scanning 0.1f as long double)
static int scan1(long double *x, char *s, int fmt)
{
	double d;
	float f;

	if (fmt == 'd') {
		if (sscanf(s, "%lf", &d) != 1)
			return -1;
		*x = d;
	} else if (fmt == 'f') {
		if (sscanf(s, "%f", &f) != 1)
			return -1;
		*x = f;
	} else if (fmt == 'l') {
		return sscanf(s, "%Lf", x) != 1;
	} else
		return -1;
	return 0;
}

static int scan(const char *fmt, struct t *t, char *buf)
{
	char *a[20];
	long double *b[4];
	long double dy, dy2;
	char *end;
	int n, i=0, j=0;

	buf = skipstr(buf, "T \t\r\n,(){}");
	n = splitstr(a, sizeof a/sizeof *a, buf, " \t\r\n,(){}");
	if (n <= 0)
		return -1;
	if (a[0][0] == 'R') {
		if (rconv(&t->r, a[i++]))
			return -1;
	} else
		t->r = RN;

	b[0] = &t->x;
	b[1] = &t->x2;
	b[2] = &t->x3;
	b[3] = 0;
	for (; *fmt && *fmt != '_'; fmt++) {
		if (i >= n)
			return -1;
		if (*fmt == 'i') {
			t->i = strtoll(a[i++], &end, 0);
			if (*end)
				return -1;
		} else if (*fmt == 'd' || *fmt == 'f' || *fmt == 'l') {
			if (scan1(b[j++], a[i++], *fmt))
				return -1;
		} else
			return -1;
	}

	b[0] = &t->y;
	b[1] = &dy;
	b[2] = &t->y2;
	b[3] = &dy2;
	j = 0;
	fmt++;
	for (; *fmt && i < n && j < sizeof b/sizeof *b; fmt++) {
		if (*fmt == 'i') {
			t->i = strtoll(a[i++], &end, 0);
			if (*end)
				return -1;
		} else if (*fmt == 'd' || *fmt == 'f' || *fmt == 'l') {
			if (scan1(b[j++], a[i++], *fmt))
				return -1;
			if (i < n && scan1(b[j++], a[i++], 'f'))
				return -1;
		} else
			return -1;
	}
	t->dy = dy;
	t->dy2 = dy2;
	if (i < n)
		econv(&t->e, a[i]);
	return 0;
}

/* assume strlen(old) == strlen(new) */
static void replace(char *buf, char *old, char *new)
{
	int n = strlen(new);
	char *p = buf;

	while ((p = strstr(p, old)))
		memcpy(p, new, n);
}

static void fixl(char *buf)
{
	replace(buf, "-infL", " -inf");
	replace(buf, "infL", " inf");
	replace(buf, "-nanL", " -nan");
	replace(buf, "nanL", " nan");
}

static int print1(char *buf, int n, long double x, int fmt)
{
	int k;

	if (fmt == 'd')
		k = snprintf(buf, n, ",%24a", (double)x);
	else if (fmt == 'f')
		k = snprintf(buf, n, ",%16a", (double)x);
	else if (fmt == 'l') {
#if LDBL_MANT_DIG == 53
		k = snprintf(buf, n, ",%24a", (double)x);
#elif LDBL_MANT_DIG == 64
		k = snprintf(buf, n, ",%30LaL", x);
		fixl(buf);
#endif
	} else
		k = -1;
	return k;
}

static int print(const char *fmt, struct t *t, char *buf, int n)
{
	long double a[4];
	int k, i=0, out=0;

	k = snprintf(buf, n, "T(%s", rstr(t->r));
	if (k < 0 || k >= n)
		return -1;
	n -= k;
	buf += k;

	a[0] = t->x;
	a[1] = t->x2;
	a[2] = t->x3;
	for (; *fmt; fmt++) {
		if (*fmt == '_') {
			a[0] = t->y;
			a[1] = t->dy;
			a[2] = t->y2;
			a[3] = t->dy2;
			i = 0;
			out = 1;
			continue;
		}
		if (*fmt == 'i') {
			k = snprintf(buf, n, ", %11lld", t->i);
			if (k < 0 || k >= n)
				return -1;
			n -= k;
			buf += k;
		} else {
			if (i >= sizeof a/sizeof *a)
				return -1;
			k = print1(buf, n, a[i++], *fmt);
			if (k < 0 || k >= n)
				return -1;
			n -= k;
			buf += k;
			if (out) {
				k = print1(buf, n, a[i++], 'f');
				if (k < 0 || k >= n)
					return -1;
				n -= k;
				buf += k;
			}
		}
	}
	k = snprintf(buf, n, ", %s)\n", estr(t->e));
	if (k < 0 || k >= n)
		return -1;
	return 0;
}
