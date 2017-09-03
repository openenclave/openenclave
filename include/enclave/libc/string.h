#ifndef __ELIBC_STRING_H
#define __ELIBC_STRING_H

#include <features.h>
#include <bits/alltypes.h>
#include <strings.h>

__ELIBC_BEGIN

size_t strlen(const char *s);

void *memset(void *s, int c, size_t n);

void *memcpy(void *dest, const void *src, size_t n);

int memcmp(const void *s1, const void *s2, size_t n);

void *memmove(void *dest, const void *src, size_t n);

size_t strcspn(const char *s, const char *c);

char *strrchr(const char *s, int c);

int strerror_r(int errnum, char *buf, size_t buflen);

char *strerror(int errnum);

char *__strdup(const char *s);

char *strchr(const char *s, int c);

char *strrchr(const char *s, int c);

void *memchr(const void *s, int c, size_t n);

void *memrchr(const void *s, int c, size_t n);

char *strstr(const char *haystack, const char *needle);

char *__stpcpy(char *d, const char *s);

void *__memrchr(const void *m, int c, size_t n);

size_t strspn(const char *s, const char *c);

char *strndup(const char *s, size_t n);

size_t strnlen(const char *s, size_t maxlen);

char *__stpncpy(char *d, const char *s, size_t n);

void *mempcpy(void *dest, const void *src, size_t n);

char *strpbrk(const char *s, const char *accept);

char *__strchrnul(const char *s, int c);

void *memccpy(void *dest, const void *src, int c, size_t n);

void *memmem(const void *haystack, size_t haystacklen, const void *needle, 
    size_t needlelen);

char *strstr(const char *haystack, const char *needle);

char *strcasestr(const char *haystack, const char *needle);

char *strcat(char *dest, const char *src);

char *strncat(char *dest, const char *src, size_t n);

size_t strlcat(char *dest, const char *src, size_t n);

size_t strlcpy(char *dest, const char *src, size_t n);

int strcmp(const char *s1, const char *s2);

int strcoll(const char *s1, const char *s2);

int strncmp(const char *s1, const char *s2, size_t n);

char *strcpy(char *dest, const char *src);

size_t strxfrm(char *dest, const char *src, size_t n);

char *strncpy(char *dest, const char *src, size_t n);

char *strsep(char **stringp, const char *delim);

char *strtok(char *str, const char *delim);

char *strtok_r(char *str, const char *delim, char **saveptr);

int strverscmp(const char *s1, const char *s2);

char *strdup(const char *s);

char *strdup_u(const char *s);

__ELIBC_END

#endif /*__ELIBC_STRING_H */
