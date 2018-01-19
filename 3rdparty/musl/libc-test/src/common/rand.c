#include <float.h>
#include <stdint.h>
#include <stdlib.h>

// TODO: use large period prng
static uint64_t seed = -1;
static uint32_t rand32(void)
{
	seed = 6364136223846793005ULL*seed + 1;
	return seed >> 32;
}
static uint64_t rand64(void)
{
	uint64_t u = rand32();
	return u<<32 | rand32();
}
static double frand()
{
	return rand64() * 0x1p-64;
}
static float frandf()
{
	return rand32() * 0x1p-32f;
}
static long double frandl()
{
	return rand64() * 0x1p-64L
#if LDBL_MANT_DIG > 64
+ rand64() * 0x1p-128L
#endif
;
}

void t_randseed(uint64_t s)
{
	seed = s;
}

/* uniform random in [0,n), n > 0 must hold */
uint64_t t_randn(uint64_t n)
{
	uint64_t r, m;

	/* m is the largest multiple of n */
	m = -1;
	m -= m%n;
	while ((r = rand64()) >= m);
	return r%n;
}

/* uniform on [a,b], a <= b must hold */
uint64_t t_randint(uint64_t a, uint64_t b)
{
	uint64_t n = b - a + 1;
	if (n)
		return a + t_randn(n);
	return rand64();
}

/* shuffle the elements of p and q until the elements in p are well shuffled */
static void shuffle2(uint64_t *p, uint64_t *q, size_t np, size_t nq)
{
	size_t r;
	uint64_t t;

	while (np) {
		r = t_randn(nq+np--);
		t = p[np];
		if (r < nq) {
			p[np] = q[r];
			q[r] = t;
		} else {
			p[np] = p[r-nq];
			p[r-nq] = t;
		}
	}
}

/* shuffle the elements of p */
void t_shuffle(uint64_t *p, size_t n)
{
	shuffle2(p,0,n,0);
}

void t_randrange(uint64_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		p[i] = i;
	t_shuffle(p, n);
}

/* hash table insert, 0 means empty, v > 0 must hold, len is power-of-2 */
static int insert(uint64_t *tab, size_t len, uint64_t v)
{
	size_t i = v & (len-1);
	size_t j = 1;

	while (tab[i]) {
		if (tab[i] == v)
			return -1;
		i += j++;
		i &= len-1;
	}
	tab[i] = v;
	return 0;
}

/* choose k unique numbers from [0,n), k <= n */
int t_choose(uint64_t n, size_t k, uint64_t *p)
{
	uint64_t *tab;
	size_t i, j, len;

	if (n < k)
		return -1;

	if (n < 16) {
		/* no alloc */
		while (k)
			if (t_randn(n--) < k)
				p[--k] = n;
		return 0;
	}

	if (k < 8) {
		/* no alloc, n > 15 > 2*k */
		for (i = 0; i < k;) {
			p[i] = t_randn(n);
			for (j = 0; p[j] != p[i]; j++);
			if (j == i)
				i++;
		}
		return 0;
	}

	// TODO: if k < n/k use k*log(k) solution without alloc

	if (n < 5*k && (n-k)*sizeof *tab < (size_t)-1) {
		/* allocation is n-k < 4*k */
		tab = malloc((n-k) * sizeof *tab);
		if (!tab)
			return -1;
		for (i = 0; i < k; i++)
			p[i] = i;
		for (; i < n; i++)
			tab[i-k] = i;
		if (k < n-k)
			shuffle2(p, tab, k, n-k);
		else
			shuffle2(tab, p, n-k, k);
		free(tab);
		return 0;
	}

	/* allocation is 2*k <= len < 4*k */
	for (len = 16; len < 2*k; len *= 2);
	tab = calloc(len, sizeof *tab);
	if (!tab)
		return -1;
	for (i = 0; i < k; i++)
		while (insert(tab, len, t_randn(n)+1));
	for (i = 0; i < len; i++)
		if (tab[i])
			*p++ = tab[i]-1;
	free(tab);
	return 0;
}

