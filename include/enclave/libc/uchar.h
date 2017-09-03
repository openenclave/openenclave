#ifndef __ELIBC_UCHAR_H
#define __ELIBC_UCHAR_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

size_t c16rtomb(char *__restrict, char16_t, mbstate_t *__restrict);

size_t mbrtoc16(char16_t *__restrict, const char *__restrict, size_t, 
    mbstate_t *__restrict);

size_t c32rtomb(char *__restrict, char32_t, mbstate_t *__restrict);

size_t mbrtoc32(char32_t *__restrict, const char *__restrict, size_t, 
    mbstate_t *__restrict);

__ELIBC_END

#endif /* __ELIBC_UCHAR_H */
