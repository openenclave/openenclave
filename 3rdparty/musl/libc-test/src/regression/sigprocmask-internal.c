// commit: a49c119276742d7d212fb88f83a8f559ca549e72 2011-02-19
// commit: 96f2197494791f5884c01b5caa908074cc7e90a6 2011-02-20
// commit: 23815f88df6c45247f3755dc7857f4013264c04f 2013-07-18
// implementation signals should not be masked
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "test.h"

int main(void)
{
	sigset_t s;
	int i;

	sigemptyset(&s);
	for (i = 32; i < SIGRTMIN; i++) {
		sigaddset(&s, i);
		if (sigismember(&s, i) == 1)
			t_error("sigaddset(&s, %d) set implementation internal rt signal\n", i);
	}
	if (sigprocmask(SIG_BLOCK, &s, 0))
		t_error("blocking signals failed: %s\n", strerror(errno));
	if (sigprocmask(SIG_BLOCK, 0, &s))
		t_error("querying sigmask failed: %s\n", strerror(errno));
	for (i = 32; i < SIGRTMIN; i++)
		if (sigismember(&s, i) == 1)
			t_error("implementation internal rt signal %d can be blocked\n", i);
	return t_status;
}
