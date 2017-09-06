#ifndef __ELIBC_WCHAR_H
#define __ELIBC_WCHAR_H

#include <features.h>
#include <bits/alltypes.h>
#include <wctype.h>
#include <stdlib.h>

__ELIBC_BEGIN

int wcsncasecmp(const wchar_t *s1, const wchar_t *s2, size_t n);

wchar_t *wcsdup(const wchar_t *s);

size_t wcslen(const wchar_t *s);

wchar_t *wmemcpy(wchar_t *s1, const wchar_t *s2, size_t n);

size_t wcscspn(const wchar_t *s, const wchar_t *c);

wchar_t *wcschr(const wchar_t *s, wchar_t wc);

wchar_t *wcpcpy(wchar_t *dest, const wchar_t *src);;

wchar_t *wcscpy(wchar_t *dest, const wchar_t *src);

size_t wcsxfrm(wchar_t *dest, const wchar_t *src, size_t n);

wchar_t *wcstok(wchar_t *wcs, const wchar_t *delim, wchar_t **ptr);

size_t wcsspn(const wchar_t *wcs, const wchar_t *accept);

wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n);

wchar_t *wcspbrk(const wchar_t *wcs, const wchar_t *accept);

wchar_t *wcswcs(const wchar_t *haystack, const wchar_t *needle);

wchar_t *wcsstr(const wchar_t *haystack, const wchar_t *needle);

int wcscasecmp(const wchar_t *s1, const wchar_t *s2);

int wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t n);

wchar_t *wcpncpy(wchar_t *dest, const wchar_t *src, size_t n);

wchar_t *wcsncpy(wchar_t *dest, const wchar_t *src, size_t n);

size_t wcsnlen(const wchar_t *s, size_t maxlen);

int wcscasecmp_l(const wchar_t *l, const wchar_t *r, locale_t locale);

wchar_t *wcscat(wchar_t *dest, const wchar_t *src);

int wcscmp(const wchar_t *s1, const wchar_t *s2);

int wcscoll(const wchar_t *s1, const wchar_t *s2);

int wcsncasecmp_l(const wchar_t *s1, const wchar_t *s2, size_t n, 
    locale_t locale);

int wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t n);

wchar_t *wmemset(wchar_t *wcs, wchar_t wc, size_t n);

wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n);

wchar_t *wcsrchr(const wchar_t *wcs, wchar_t wc);

wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n);

int wcswidth(const wchar_t *wcs, size_t n);

int wcwidth(wchar_t c);

wint_t btowc(int c);

size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps);

size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);

size_t mbrlen(const char *s, size_t n, mbstate_t *ps);

int mbsinit(const mbstate_t *ps);

size_t mbsnrtowcs(wchar_t *dest, const char **src, size_t nms, size_t len, 
    mbstate_t *ps);

size_t mbsrtowcs(wchar_t *dest, const char **src, size_t len, mbstate_t *ps);

size_t wcsnrtombs(char *dest, const wchar_t **src, size_t nwc, size_t len, 
    mbstate_t *ps);

size_t wcsrtombs(char *dest, const wchar_t **src, size_t len, mbstate_t *ps);

int wctob(wint_t c);

long int wcstol(const wchar_t *nptr, wchar_t **endptr, int base);

unsigned long int wcstoul(const wchar_t *nptr, wchar_t **endptr, int base);

long long int wcstoll(const wchar_t *nptr, wchar_t **endptr, int base);

unsigned long long int wcstoull(const wchar_t *nptr, wchar_t **endptr, 
    int base);

float wcstof(const wchar_t *nptr, wchar_t **endptr);

double wcstod(const wchar_t *nptr, wchar_t **endptr);

long double wcstold(const wchar_t *nptr, wchar_t **endptr);

int swprintf(wchar_t *wcs, size_t maxlen, const wchar_t *format, ...);

int vswprintf(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args);

__ELIBC_END

#endif /* __ELIBC_WCHAR_H */
