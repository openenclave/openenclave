#include <wctype.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(wint_t)
T(wctrans_t)
T(wctype_t)
#ifdef _POSIX_C_SOURCE
T(locale_t)
#endif
C(WEOF)
{int(*p)(wint_t) = iswalnum;}
{int(*p)(wint_t) = iswalpha;}
{int(*p)(wint_t) = iswblank;}
{int(*p)(wint_t) = iswcntrl;}
{int(*p)(wint_t,wctype_t) = iswctype;}
{int(*p)(wint_t) = iswdigit;}
{int(*p)(wint_t) = iswgraph;}
{int(*p)(wint_t) = iswlower;}
{int(*p)(wint_t) = iswprint;}
{int(*p)(wint_t) = iswpunct;}
{int(*p)(wint_t) = iswspace;}
{int(*p)(wint_t) = iswupper;}
{int(*p)(wint_t) = iswxdigit;}
{wint_t(*p)(wint_t,wctrans_t) = towctrans;}
{wint_t(*p)(wint_t) = towlower;}
{wint_t(*p)(wint_t) = towupper;}
{wctrans_t(*p)(const char*) = wctrans;}
{wctype_t(*p)(const char*) = wctype;}
#ifdef _POSIX_C_SOURCE
{int(*p)(wint_t,locale_t) = iswalnum_l;}
{int(*p)(wint_t,locale_t) = iswalpha_l;}
{int(*p)(wint_t,locale_t) = iswblank_l;}
{int(*p)(wint_t,locale_t) = iswcntrl_l;}
{int(*p)(wint_t,wctype_t,locale_t) = iswctype_l;}
{int(*p)(wint_t,locale_t) = iswdigit_l;}
{int(*p)(wint_t,locale_t) = iswgraph_l;}
{int(*p)(wint_t,locale_t) = iswlower_l;}
{int(*p)(wint_t,locale_t) = iswprint_l;}
{int(*p)(wint_t,locale_t) = iswpunct_l;}
{int(*p)(wint_t,locale_t) = iswspace_l;}
{int(*p)(wint_t,locale_t) = iswupper_l;}
{int(*p)(wint_t,locale_t) = iswxdigit_l;}
{wint_t(*p)(wint_t,wctrans_t,locale_t) = towctrans_l;}
{wint_t(*p)(wint_t,locale_t) = towlower_l;}
{wint_t(*p)(wint_t,locale_t) = towupper_l;}
{wctrans_t(*p)(const char*,locale_t) = wctrans_l;}
{wctype_t(*p)(const char*,locale_t) = wctype_l;}
#endif
}
