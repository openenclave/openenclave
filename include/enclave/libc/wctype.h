#ifndef __ELIBC_WCTYPE_H
#define __ELIBC_WCTYPE_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

int iswalnum(wint_t wc);
int iswalpha(wint_t wc);
int iswblank(wint_t wc);
int iswcntrl(wint_t wc);
int iswdigit(wint_t wc);
int iswgraph(wint_t wc);
int iswlower(wint_t wc);
int iswprint(wint_t wc);
int iswpunct(wint_t wc);
int iswspace(wint_t wc);
int iswupper(wint_t wc);
int iswxdigit(wint_t wc);
int iswctype(wint_t wc, wctype_t desc);
wint_t towlower(wint_t wc);
wint_t towupper(wint_t wc);
wctype_t wctype(const char *s);
wctrans_t wctrans(const char *s);
wint_t towctrans(wint_t wc, wctrans_t desc);

int __iswalnum_l(wint_t c, locale_t l);
int __iswalpha_l(wint_t c, locale_t l);
int __iswblank_l(wint_t c, locale_t l);
int __iswcntrl_l(wint_t c, locale_t l);
int __iswdigit_l(wint_t c, locale_t l);
int __iswgraph_l(wint_t c, locale_t l);
int __iswlower_l(wint_t c, locale_t l);
int __iswprint_l(wint_t c, locale_t l);
int __iswpunct_l(wint_t c, locale_t l);
int __iswspace_l(wint_t c, locale_t l);
int __iswupper_l(wint_t c, locale_t l);
int __iswxdigit_l(wint_t c, locale_t l);
int __iswctype_l(wint_t c, wctype_t t, locale_t l);
wint_t __towlower_l(wint_t c, locale_t l);
wint_t __towupper_l(wint_t c, locale_t l);
wctype_t __wctype_l(const char *s, locale_t l);
wctrans_t __wctrans_l(const char *s, locale_t l);
wint_t __towctrans_l(wint_t c, wctrans_t t, locale_t l);

int iswalnum_l(wint_t c, locale_t l);
int iswalpha_l(wint_t c, locale_t l);
int iswblank_l(wint_t c, locale_t l);
int iswcntrl_l(wint_t c, locale_t l);
int iswdigit_l(wint_t c, locale_t l);
int iswgraph_l(wint_t c, locale_t l);
int iswlower_l(wint_t c, locale_t l);
int iswprint_l(wint_t c, locale_t l);
int iswpunct_l(wint_t c, locale_t l);
int iswspace_l(wint_t c, locale_t l);
int iswupper_l(wint_t c, locale_t l);
int iswxdigit_l(wint_t c, locale_t l);
int iswctype_l(wint_t c, wctype_t t, locale_t l);
wint_t towlower_l(wint_t c, locale_t l);
wint_t towupper_l(wint_t c, locale_t l);
wctype_t wctype_l(const char *s, locale_t l);
wctrans_t wctrans_l(const char *s, locale_t l);
wint_t towctrans_l(wint_t c, wctrans_t t, locale_t l);

__ELIBC_END

#endif /* __ELIBC_WCTYPE_H */
