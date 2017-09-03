#ifndef __ELIBC_STDLIB_H
#define __ELIBC_STDLIB_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#define MB_CUR_MAX ((size_t) + 4)

/* 
**==============================================================================
**
** abort()
**
**==============================================================================
*/

__NORETURN void abort(void);

/* 
**==============================================================================
**
** Divide functions
**
**==============================================================================
*/

typedef struct 
{
    int quot;
    int rem;
} 
div_t;

__ELIBC_INLINE div_t div(int numerator, int denominator)
{
    div_t r;
    r.quot = numerator / denominator;
    r.rem = numerator % denominator;
    return r;
}

typedef struct 
{
    long quot;
    long rem;
} 
ldiv_t;

__ELIBC_INLINE ldiv_t ldiv(long numerator, long denominator)
{
    ldiv_t r;
    r.quot = numerator / denominator;
    r.rem = numerator % denominator;
    return r;
}

typedef struct 
{
    long long quot;
    long long rem;
} 
lldiv_t;

__ELIBC_INLINE lldiv_t lldiv(long long numerator, long long denominator)
{
    lldiv_t r;
    r.quot = numerator / denominator;
    r.rem = numerator % denominator;
    return r;
}

/* 
**==============================================================================
**
** Absolute value of integers:
**
**==============================================================================
*/

int abs(int x);

long labs(long x);

long long llabs(long long x);

/* 
**==============================================================================
**
** memory allocation
**
**==============================================================================
*/

void* malloc(size_t size);

void* malloc_u(size_t size);

void free(void* ptr);

void free_u(void* ptr);

void* calloc(size_t nmemb, size_t size);

void* calloc_u(size_t nmemb, size_t size);

void* realloc(void* ptr, size_t size);

void* realloc_u(void* ptr, size_t size);

void* memalign(size_t alignment, size_t size);

int posix_memalign(void** memptr, size_t alignment, size_t size);

/*
**==============================================================================
**
** multi-byte functions:
**
**==============================================================================
*/

int mblen(const char *s, size_t n);

size_t mbstowcs(wchar_t *dest, const char *src, size_t n);

int wctomb(char *s, wchar_t wc);

int mbtowc(wchar_t *pwc, const char *s, size_t n);

size_t wcstombs(char *dest, const wchar_t *src, size_t n);

/*
**==============================================================================
**
** qsort()
**
**==============================================================================
*/

void qsort(
    void *base, 
    size_t nmemb, 
    size_t size,
    int (*compar)(const void *, const void *));

/*
**==============================================================================
**
** bsearch()
**
**==============================================================================
*/

void* bsearch(
    const void *key, 
    const void *base, 
    size_t nmemb, 
    size_t size, 
    int (*compar)(const void *, const void *));

/*
**==============================================================================
**
** String-to-integer converters:
**
**==============================================================================
*/

long int strtol(const char *nptr, char **endptr, int base);

unsigned long int strtoul(const char *nptr, char **endptr, int base);

long long int strtoll(const char *nptr, char **endptr, int base);

unsigned long long int strtoull(const char *nptr, char **endptr, int base);

int atoi(const char *nptr);

long atol(const char *nptr);

long long atoll(const char *nptr);

/*
**==============================================================================
**
** String-to-real converters:
**
**==============================================================================
*/

float strtof(const char *nptr, char **endptr);

double strtod(const char *nptr, char **endptr);

long double strtold(const char *nptr, char **endptr);

#ifndef __ELIBC_NO_STRTOF_L_PROTOTYPE
float strtof_l(const char *, char **, locale_t loc);
#endif

#ifndef __ELIBC_NO_STRTOD_L_PROTOTYPE
double strtod_l(const char *nptr, char **endptr, locale_t loc);
#endif

#ifndef __ELIBC_NO_STRTOLD_L_PROTOTYPE
long double strtold_l(const char *nptr, char **endptr, locale_t loc);
#endif

double atof(const char *nptr);

/*
**==============================================================================
**
** Random numbers
**
**==============================================================================
*/

void srand(unsigned s);

int rand(void);

/*
**==============================================================================
**
** Miscelaneous
**
**==============================================================================
*/

#ifdef __ELIBC_UNSUPPORTED
char *getenv(const char *name);
#endif

#ifdef __ELIBC_UNSUPPORTED
int atexit(void (*function)(void));
#endif

__ELIBC_END

#endif /* __ELIBC_STDLIB_H */
