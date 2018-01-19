#include <time.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(clock_t)
T(size_t)
T(time_t)
#ifdef _POSIX_C_SOURCE
T(clockid_t)
T(timer_t)
T(locale_t)
T(pid_t)
T(struct sigevent)
{
struct timespec x;
F(time_t,tv_sec)
F(long,tv_nsec)
}
{
struct itimerspec x;
F(struct timespec,it_interval)
F(struct timespec,it_value)
}
C(CLOCK_MONOTONIC)
C(CLOCK_PROCESS_CPUTIME_ID)
C(CLOCK_REALTIME)
C(CLOCK_THREAD_CPUTIME_ID)
#endif
{
struct tm x;
F(int,tm_sec)
F(int,tm_min)
F(int,tm_hour)
F(int,tm_mday)
F(int,tm_mon)
F(int,tm_year)
F(int,tm_wday)
F(int,tm_yday)
F(int,tm_isdst)
}
{void *x = NULL;}
{int x = CLOCKS_PER_SEC;}
C(TIMER_ABSTIME)
{char*(*p)(const struct tm*) = asctime;}
{clock_t(*p)(void) = clock;}
{char*(*p)(const time_t*) = ctime;}
{double(*p)(time_t,time_t) = difftime;}
{struct tm*(*p)(const time_t*) = gmtime;}
{struct tm*(*p)(const time_t*) = localtime;}
{time_t(*p)(struct tm*) = mktime;}
{size_t(*p)(char*restrict,size_t,const char*restrict,const struct tm*restrict) = strftime;}
{time_t(*p)(time_t*) = time;}
#ifdef _POSIX_C_SOURCE
{char*(*p)(const struct tm*restrict,char*restrict) = asctime_r;}
{int(*p)(pid_t,clockid_t*) = clock_getcpuclockid;}
{int(*p)(clockid_t,struct timespec*) = clock_getres;}
{int(*p)(clockid_t,struct timespec*) = clock_gettime;}
{int(*p)(clockid_t,int,const struct timespec*,struct timespec*) = clock_nanosleep;}
{int(*p)(clockid_t,const struct timespec*) = clock_settime;}
{char*(*p)(const time_t*,char*) = ctime_r;}
{struct tm*(*p)(const time_t*restrict,struct tm*restrict) = gmtime_r;}
{struct tm*(*p)(const time_t*restrict,struct tm*restrict) = localtime_r;}
{int(*p)(const struct timespec*,struct timespec*) = nanosleep;}
{size_t(*p)(char*restrict,size_t,const char*restrict,const struct tm*restrict,locale_t) = strftime_l;}
{int(*p)(clockid_t,struct sigevent*restrict,timer_t*restrict) = timer_create;}
{int(*p)(timer_t) = timer_delete;}
{int(*p)(timer_t) = timer_getoverrun;}
{int(*p)(timer_t,struct itimerspec*) = timer_gettime;}
{int(*p)(timer_t,int,const struct itimerspec*restrict,struct itimerspec*restrict) = timer_settime;}
{char **x = tzname;}
{void(*p)(void) = tzset;}
#endif
#ifdef _XOPEN_SOURCE
{struct tm*(*p)(const char*) = getdate;}
{int i = getdate_err;}
{char*(*p)(const char*restrict,const char*restrict,struct tm*restrict) = strptime;}
{long i = timezone;}
{int i = daylight;}
#endif
}
