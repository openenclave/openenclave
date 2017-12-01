#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static uint64_t seed = -1;
static uint32_t rand32(void)
{
	seed = 6364136223846793005ull*seed + 1;
	return seed >> 32;
}
static uint64_t rand64(void)
{
	uint64_t u = rand32();
	return u<<32 | rand32();
}
static double frand(){return rand64() * 0x1p-64;}
static float frandf(){return rand32() * 0x1p-32f;}
static long double frandl(){return rand64() * 0x1p-64L;}

/* uniform random in [0,n), n > 0 must hold */
uint64_t randn(uint64_t n)
{
	uint64_t r, m;

	/* m is the largest multiple of n */
	m = -1;
	m -= m%n;
	while ((r = rand64()) >= m);
	return r%n;
}

/* uniform on [a,b] */
uint64_t randint(uint64_t a, uint64_t b)
{
	if (b < a) {
		uint64_t t = b;
		b = a;
		a = t;
	}
	return a + randn(b - a + 1);
}

int insert(uint64_t *tab, size_t len, uint64_t v)
{
	size_t i = v & (len-1);
	size_t j = 1;

	/* 0 means empty, v > 0 must hold */
	while (tab[i]) {
		if (tab[i] == v)
			return -1;
		i += j++;
		i &= len-1;
	}
	tab[i] = v;
	return 0;
}

static void shuffle2(uint64_t *p, uint64_t *q, size_t np, size_t nq)
{
	size_t i,r,t;

	i = np+nq;
	while (i > np) {
		r = randn(i);
		i--;
		t = q[i-np];
		if (r < np) {
			q[i-np] = p[r];
			p[r] = t;
		} else {
			q[i-np] = q[r-np];
			q[r-np] = t;
		}
	}
}

/* choose k unique numbers from [0,n), k <= n */
int choose(uint64_t n, size_t k, uint64_t *p)
{
	uint64_t *tab;
	size_t i, j, len;

	if (n < k)
		return -1;

	if (n < 16) {
		/* no alloc */
		while (k)
			if (randn(n--) < k)
				p[--k] = n;
		return 0;
	}

	if (k < 8) {
		/* no alloc, n > 15 > 2*k */
		for (i = 0; i < k;) {
			p[i] = randn(n);
			for (j = 0; p[j] != p[i]; j++);
			if (j == i)
				i++;
		}
		return 0;
	}

	if (n < 5*k && (n-k)*sizeof *tab < (size_t)-1) {
		/* allocation is < 4*k */
		tab = malloc((n-k) * sizeof *tab);
		if (!tab)
			return -1;
		for (i = 0; i < k; i++)
			p[i] = i;
		for (; i < n; i++)
			tab[i-k] = i;
		if (n-k < k)
			shuffle2(p, tab, k, n-k);
		else
			shuffle2(tab, p, n-k, k);
		free(tab);
		return 0;
	}

	/* allocation is < 4*k */
	for (len = 16; len <= 2*k; len *= 2);
	tab = calloc(len, sizeof *tab);
	if (!tab)
		return -1;
	for (i = 0; i < k; i++)
		while (insert(tab, len, randn(n)+1));
	for (i = 0; i < len; i++)
		if (tab[i])
			*p++ = tab[i]-1;
	free(tab);
	return 0;
}

static int cmp64(const void *a, const void *b)
{
	const uint64_t *ua = a, *ub = b;
	return *ua < *ub ? -1 : (*ua > *ub ? 1 : 0);
}

// todo: in place flip problem

/* choose k unique uint64_t numbers */
int choose64(size_t k, uint64_t *p)
{
	size_t i, c;

	/* no alloc, collisions should be very rare */
	for (i = 0; i < k; i++)
		p[i] = rand64();
	do {
		c = 0;
		qsort(p, k, sizeof *p, cmp64);
		for (i = 1; i < k; i++)
			if (p[i] == p[i-1]) {
				p[i-1] = rand64();
				c = 1;
			}
	} while (c);
	return 0;
}

/* equidistant sampling with some randomness */
int sample(uint64_t n, size_t k, uint64_t *p)
{
	uint64_t a = 0;
	uint64_t d = n/k;
	size_t m = n%k;
	size_t i, j;
	uint64_t *q;

	if (!d)
		return -1;
	q = malloc((m+1) * sizeof *q);
	if (!q)
		return -1;
	if (choose(k, m, q))
		return -1;
	qsort(q, m, sizeof *q, cmp64);
	q[m] = k;
	for (i = j = 0; i < k; i++) {
		uint64_t t;

		while (q[j] < i)
			j++;
		if (q[j] == i)
			t = d+1;
		else
			t = d;
		p[i] = a + randn(t);
		a += t;
	}
	free(q);
	return 0;
}

/* [-inf,inf] uniform on representation */
int genall(size_t k, uint64_t *p)
{
	size_t i;
	uint64_t n, d;
	d = 1;
	d <<= 52;
	if (sample(-2*d, k, p))
		return -1;
	n = 0x7ff;
	n <<= 52;
	for (i = 0; i < k; i++)
		if (p[i] > n)
			p[i] += d-1;
	return 0;
}

/* [a,b) uniform on representation, 0 <= a <= b */
int genab(size_t k, uint64_t a, uint64_t b, uint64_t *p)
{
	size_t i;

	if (sample(b-a, k, p))
		return -1;
	for (i = 0; i < k; i++)
		p[i] += a;
	return 0;
}

#define asfloat(x) ((union{uint64_t af_i; double af_f;}){.af_i=x}.af_f)
#define asint(x)   ((union{uint64_t af_i; double af_f;}){.af_f=x}.af_i)

int main(int argc, char *argv[])
{
	uint64_t k, i;
	uint64_t *p;
	double a,b,m;
	char *e;
	int opt;

	k = 1000;
	a = 0;
	b = 1;
	m = 1;
	while ((opt = getopt(argc, argv, "n:a:b:m:s:")) != -1) {
		switch(opt) {
		case 'n':
			k = strtoull(optarg,&e,0);
			break;
		case 'a':
			a = strtod(optarg,&e);
			if (a < 0)
				goto usage;
			break;
		case 'b':
			b = strtod(optarg,&e);
			if (b < 0)
				goto usage;
			break;
		case 'm':
			m = strtod(optarg,&e);
			break;
		case 's':
			seed = strtoull(optarg,&e,0);
			break;
		default:
usage:
			fprintf(stderr, "usage: %s -n num -a absmin -b absmax -m mult -s seed\n", argv[0]);
			return -1;
		}
		if (*e || errno)
			goto usage;
	}
	if (!(a <= b))
		goto usage;
	p = malloc(k * sizeof *p);
	if (!p)
		return -1;
	if (genab(k, asint(a), asint(b), p))
//	if (genall(k,p))
		return -1;
	for (i = 0; i < k; i++)
//		printf("0x%016llx\n", p[i]);
		printf("%a\n", m*asfloat(p[i]));
	return 0;
}
