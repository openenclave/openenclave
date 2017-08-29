#ifndef __ELIBC_STRINGS_H
#define __ELIBC_STRINGS_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

char *index(const char *s, int c);

char *rindex(const char *s, int c);

void bcopy(const void *s1, void *s2, size_t n);

int bcmp(const void *s1, const void *s2, size_t n);

void bzero(void *s, size_t n);

int strcasecmp(const char *s1, const char *s2);

int strncasecmp(const char *s1, const char *s2, size_t n);

int __strcasecmp_l(const char *l, const char *r, locale_t loc);

int __strncasecmp_l(const char *l, const char *r, size_t n, locale_t loc);

__ELIBC_END

#endif /*__ELIBC_STRINGS_H */
