#include <locale.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(locale_t)
{
struct lconv x;
F(char*,currency_symbol)
F(char*,decimal_point)
F(char,frac_digits)
F(char*,grouping)
F(char*,int_curr_symbol)
F(char,int_frac_digits)
F(char,int_n_cs_precedes)
F(char,int_n_sep_by_space)
F(char,int_n_sign_posn)
F(char,int_p_cs_precedes)
F(char,int_p_sep_by_space)
F(char,int_p_sign_posn)
F(char*,mon_decimal_point)
F(char*,mon_grouping)
F(char*,mon_thousands_sep)
F(char*,negative_sign)
F(char,n_cs_precedes)
F(char,n_sep_by_space)
F(char,n_sign_posn)
F(char*,positive_sign)
F(char,p_cs_precedes)
F(char,p_sep_by_space)
F(char,p_sign_posn)
F(char*,thousands_sep)
}
{void *x=NULL;}
C(LC_ALL)
C(LC_COLLATE)
C(LC_CTYPE)
#ifdef _POSIX_C_SOURCE
C(LC_MESSAGES)
#endif
C(LC_MONETARY)
C(LC_NUMERIC)
C(LC_TIME)
#ifdef _POSIX_C_SOURCE
C(LC_ALL_MASK)
C(LC_COLLATE_MASK)
C(LC_CTYPE_MASK)
C(LC_MESSAGES_MASK)
C(LC_MONETARY_MASK)
C(LC_NUMERIC_MASK)
C(LC_TIME_MASK)
{locale_t x = LC_GLOBAL_LOCALE;}
{locale_t(*p)(locale_t) = duplocale;}
{void(*p)(locale_t) = freelocale;}
{locale_t(*p)(int,const char*,locale_t) = newlocale;}
{locale_t(*p)(locale_t) = uselocale;}
#endif
{struct lconv*(*p)(void) = localeconv;}
{char*(*p)(int,const char*) = setlocale;}
}
