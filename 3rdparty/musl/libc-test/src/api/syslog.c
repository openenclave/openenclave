#include <syslog.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
C(LOG_PID)
C(LOG_CONS)
C(LOG_NDELAY)
C(LOG_ODELAY)
C(LOG_NOWAIT)
C(LOG_KERN)
C(LOG_USER)
C(LOG_MAIL)
C(LOG_NEWS)
C(LOG_UUCP)
C(LOG_DAEMON)
C(LOG_AUTH)
C(LOG_CRON)
C(LOG_LPR)
C(LOG_LOCAL0)
C(LOG_LOCAL1)
C(LOG_LOCAL2)
C(LOG_LOCAL3)
C(LOG_LOCAL4)
C(LOG_LOCAL5)
C(LOG_LOCAL6)
C(LOG_LOCAL7)
{int i = LOG_MASK(0);}
C(LOG_EMERG)
C(LOG_ALERT)
C(LOG_CRIT)
C(LOG_ERR)
C(LOG_WARNING)
C(LOG_NOTICE)
C(LOG_INFO)
C(LOG_DEBUG)
{void(*p)(void) = closelog;}
{void(*p)(const char*,int,int) = openlog;}
{int(*p)(int) = setlogmask;}
{void(*p)(int,const char*,...) = syslog;}
}
