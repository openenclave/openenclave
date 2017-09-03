#ifndef __ELIBC_CTYPE_H
#define __ELIBC_CTYPE_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

int isalnum(int c);
int isalpha(int c);
int iscntrl(int c);
int isdigit(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);
int isascii(int c);
int isblank(int c);
int toupper(int c);
int tolower(int c);

int __isalnum_l(int c, locale_t l);
int __isalpha_l(int c, locale_t l);
int __isblank_l(int c, locale_t l);
int __iscntrl_l(int c, locale_t l);
int __isdigit_l(int c, locale_t l);
int __isgraph_l(int c, locale_t l);
int __islower_l(int c, locale_t l);
int __isprint_l(int c, locale_t l);
int __ispunct_l(int c, locale_t l);
int __isspace_l(int c, locale_t l);
int __isupper_l(int c, locale_t l);
int __isxdigit_l(int c, locale_t l);
int __tolower_l(int c, locale_t l);
int __toupper_l(int c, locale_t l);

int isalnum_l(int c, locale_t l);
int isalpha_l(int c, locale_t l);
int isblank_l(int c, locale_t l);
int iscntrl_l(int c, locale_t l);
int isdigit_l(int c, locale_t l);
int isgraph_l(int c, locale_t l);
int islower_l(int c, locale_t l);
int isprint_l(int c, locale_t l);
int ispunct_l(int c, locale_t l);
int isspace_l(int c, locale_t l);
int isupper_l(int c, locale_t l);
int isxdigit_l(int c, locale_t l);
int tolower_l(int c, locale_t l);
int toupper_l(int c, locale_t l);

int toascii(int c);

__ELIBC_END

#endif /* __ELIBC_CTYPE_H */
