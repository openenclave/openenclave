/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#define _CRT_FUNCTIONS_REQUIRED 0
#include <string.h>
#include <trace.h>
#ifdef OE_SIMULATE_OPTEE
#define sprintf_s oe_sprintf_s
#endif

#include <tcps_string_t.h>
#include <tcps_stdlib_t.h>

int vprintf(const char *format, va_list argptr)
{
    char buf[BUFSIZ] = { '\0' };
    _vsnprintf(buf, BUFSIZ, format, argptr);

    IMSG("%s", buf);
    return strlen(buf);
}

int vsprintf_s(
    char *buffer,
    size_t numberOfElements,
    const char *format,
    va_list argptr)
{
    return vsnprintf(buffer, numberOfElements, format, argptr);
}

int _snprintf_s(char* _Dst, size_t _SizeInBytes, size_t _Count, const char *_Format, ...)
{
    va_list _ArgList;
    va_start(_ArgList, _Format);
    size_t maxSize = (_Count < _SizeInBytes) ? _Count + 1 : _SizeInBytes;
    return _vsnprintf(_Dst, maxSize, _Format, _ArgList);
}

int sprintf_s(char* _Dst, size_t _SizeInBytes, const char *_Format, ...)
{
    va_list _ArgList;
    va_start(_ArgList, _Format);
    return vsprintf_s(_Dst, _SizeInBytes, _Format, _ArgList);
}

long strtol(const char *nptr, char **endptr, int base)
{
    const char *ptr = nptr;
    char n;
    int digit, value = 0, mult = 1;

    if ((base < 2) || (base > 16)) {
        *endptr = (char*) nptr;
        return 0;
    }

    if (ptr[0] == '-') {
        mult = -1;
        ptr++;
    }

    for (; *ptr; ptr++) {
        n = *ptr;
        if ((n >= '0') && (n <= '9')) {
            digit = n - '0';
        } else if ((n >= 'a') && (n <= 'f')) {
            digit = n - 'a';
        } else if ((n >= 'A') && (n <= 'F')) {
            digit = n - 'F';
        } else {
            break;
        }
        if (digit > base) {
            break;
        }
        value = (value * base) + digit;
        nptr++;
    }

    *endptr = (char*)ptr;
    return mult * value;
}

unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    const char *ptr = nptr;
    char n;
    int digit, value = 0;

    if ((base < 2) || (base > 16)) {
        *endptr = (char*)nptr;
        return 0;
    }

    for (; *ptr; ptr++) {
        n = *ptr;
        if ((n >= '0') && (n <= '9')) {
            digit = n - '0';
        } else if ((n >= 'a') && (n <= 'f')) {
            digit = n - 'a';
        } else if ((n >= 'A') && (n <= 'F')) {
            digit = n - 'F';
        } else {
            break;
        }
        if (digit > base) {
            break;
        }
        value = (value * base) + digit;
        nptr++;
    }

    *endptr = (char*)ptr;
    return value;
}

int atoi(const char * str)
{
    char *endptr;
    long value = strtol(str, &endptr, 10);
    return value;
}

char *strncat(char *front, const char* back, size_t count)
{
    char *start = front;

    while (*front++)
        ;
    front--;

    while (count--) {
        if (!(*front++ = *back++)) {
            return(start);
        }
    }

    *front = '\0';
    return(start);
}

#ifdef OE_SIMULATE_OPTEE
char* strncpy(char* destination, const char* source, size_t num)
{
    (void)strncpy_s(destination, num + 1, source, num);
    return destination;
}
#endif

char *strrchr(
    const char* string,
    int ch)
{
    char *start = (char*)string;

    while (*string++)           /* find end of string */
        ;
                        /* search towards front */
    while (--string != start && *string != (char)ch)
        ;

    if (*string == (char)ch)        /* char found ? */
        return( (char *)string );

    return(NULL);
}

char* oe_strstr(
    const char* str1,
    const char* str2)
{
    char *cp = (char *) str1;
    char *s1, *s2;

    if (!*str2) {
        return((char *)str1);
    }

    while (*cp) {
        s1 = cp;
        s2 = (char *) str2;

        while (*s1 && *s2 && !(*s1-*s2))
            s1++, s2++;

        if (!*s2)
            return(cp);

        cp++;
    }

    return NULL;
}

char* strerror(int errorCode)
{
    (void)errorCode;
    return (char*)"placeholder error message";
}

#ifdef __USE_CONTEXT
#define __COMPARE(context, p1, p2) (*compare)(context, p1, p2)
#else
#define __COMPARE(context, p1, p2) (*compare)(p1, p2)
#endif

#define _VALIDATE_RETURN(cond, err, result) do { if (!(cond)) return result; } while (0)

void*
bsearch(
    const void* key,
    const void* base,
    size_t num,
    size_t width,
    int (*compare)(const void*, const void*))
{
    char *lo = (char *)base;
    char *hi = (char *)base + (num - 1) * width;
    char *mid;
    size_t half;
    int result;

    /* validation section */
    _VALIDATE_RETURN(base != NULL || num == 0, EINVAL, NULL);
    _VALIDATE_RETURN(width > 0, EINVAL, NULL);
    _VALIDATE_RETURN(compare != NULL, EINVAL, NULL);

    while (lo <= hi) {
        if ((half = num / 2) != 0) {
            mid = lo + (num & 1 ? half : (half - 1)) * width;
            if (!(result = __COMPARE(context, key, mid))) {
                return(mid);
            } else if (result < 0) {
                hi = mid - width;
                num = num & 1 ? half : half-1;
            } else {
                lo = mid + width;
                num = half;
            }
        } else if (num) {
            return (__COMPARE(context, key, lo) ? NULL : lo);
        } else {
            break;
        }
    }

    return NULL;
}
