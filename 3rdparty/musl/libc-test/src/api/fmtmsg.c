#ifdef X_FMTMSG
#include <fmtmsg.h>
#define C(n) switch(n){case n:;}
static void f()
{
C(MM_HARD)
C(MM_SOFT)
C(MM_FIRM)
C(MM_APPL)
C(MM_UTIL)
C(MM_OPSYS)
C(MM_RECOVER)
C(MM_NRECOV)
C(MM_HALT)
C(MM_ERROR)
C(MM_WARNING)
C(MM_INFO)
C(MM_NOSEV)
C(MM_PRINT)
C(MM_CONSOLE)
C(MM_OK)
C(MM_NOTOK)
C(MM_NOMSG)
C(MM_NOCON)
{int(*p)(long,const char*,int,const char*,const char*,const char*) = fmtmsg;}
}
#else
static void f(){}
#endif
