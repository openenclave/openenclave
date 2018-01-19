// commit 5f95f965e933c5b155db75520ac27c92ddbcf400 2014-03-18
// syscall should not sign extend pointers on x32
#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include "test.h"

#define T(f) ((f) && (t_error(#f " failed: %s\n", strerror(errno)), 0))

static unsigned long long tsdiff(struct timespec ts2, struct timespec ts)
{
	if (ts2.tv_nsec < ts.tv_nsec) {
		ts2.tv_nsec += 1000000000;
		ts2.tv_sec--;
	}
	if (ts2.tv_sec < ts.tv_sec) {
		t_error("non-monotonic SYS_clock_gettime vs clock_gettime: %llu ns\n",
			(ts.tv_sec - ts2.tv_sec)*1000000000ULL + ts.tv_nsec - ts2.tv_nsec);
		return 0;
	}
	return (ts2.tv_sec - ts.tv_sec)*1000000000ULL + (ts2.tv_nsec - ts.tv_nsec);
}

int main(void)
{
	struct timespec ts, ts2;
	unsigned long long diff;

	// test syscall with pointer
	T(syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts));

	// check if timespec is filled correctly
	T(clock_gettime(CLOCK_REALTIME, &ts2));
	// adjust because linux vdso is non-monotonic wrt the syscall..
	ts.tv_nsec += 2;
	diff = tsdiff(ts2, ts);
	if (diff > 5 * 1000000000ULL)
		t_error("large diff between clock_gettime calls: %llu ns\n", diff);

	return t_status;
}
