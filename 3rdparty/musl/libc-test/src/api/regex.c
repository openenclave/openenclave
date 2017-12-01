#include <regex.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(size_t)
T(regoff_t)
{
regex_t x;
F(size_t,re_nsub)
}
{
regmatch_t x;
F(regoff_t,rm_so)
F(regoff_t,rm_eo)
}
C(REG_EXTENDED)
C(REG_ICASE)
C(REG_NOSUB)
C(REG_NEWLINE)
C(REG_NOTBOL)
C(REG_NOTEOL)
C(REG_NOMATCH)
C(REG_BADPAT)
C(REG_ECOLLATE)
C(REG_ECTYPE)
C(REG_EESCAPE)
C(REG_ESUBREG)
C(REG_EBRACK)
C(REG_EPAREN)
C(REG_EBRACE)
C(REG_BADBR)
C(REG_ERANGE)
C(REG_ESPACE)
C(REG_BADRPT)
{int(*p)(regex_t*restrict,const char*restrict,int) = regcomp;}
{size_t(*p)(int,const regex_t*restrict,char*restrict,size_t) = regerror;}
{int(*p)(const regex_t*restrict,const char*restrict,size_t,regmatch_t[restrict],int) = regexec;}
{void(*p)(regex_t*) = regfree;}
}
