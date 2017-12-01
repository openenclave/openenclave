// commit: 6871fd773dcedbf056317d5d5e87b4859e97c4a4 2011-03-10
// commit: 9505bfbc40fec217820abad7142663eda60cd6be 2014-03-18
// catching stackoverflow SIGSEGV using sigaltstack
// mips stack_t is inconsistent with other archs
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "test.h"

#define T(f) ((f)==0 || (t_error(#f " failed: %s\n", strerror(errno)),0))

static char stack[SIGSTKSZ];

static void handler(int sig)
{
	uintptr_t i;
	stack_t ss;

	i = (uintptr_t)&i;
	if (i < (uintptr_t)stack || i >= (uintptr_t)stack+SIGSTKSZ)
		t_error("signal handler was not invoked on the altstack\n");

	T(sigaltstack(0, &ss));
	if (ss.ss_flags != SS_ONSTACK)
		t_error("ss_flags is not SS_ONSTACK in the signal handler\n");
}

int main(void)
{
	stack_t ss;
	struct sigaction sa;

	ss.ss_sp = stack;
	ss.ss_size = sizeof stack;
	ss.ss_flags = 0;
	sa.sa_handler = handler;
	sa.sa_flags = SA_ONSTACK;

	T(sigaltstack(&ss, 0));
	T(sigfillset(&sa.sa_mask));
	T(sigaction(SIGUSR1, &sa, 0));
	T(raise(SIGUSR1));

	errno = 0;
	ss.ss_size = MINSIGSTKSZ-1;
	if (sigaltstack(&ss, 0) != -1 || errno != ENOMEM)
		t_error("sigaltstack with stack size < MINSIGSTKSZ should have failed with ENOMEM, "
			"got %s\n", strerror(errno));
	errno = 0;
	ss.ss_flags = -1;
	ss.ss_size = MINSIGSTKSZ;
	if (sigaltstack(&ss, 0) != -1 || errno != EINVAL)
		t_error("sigaltstack with bad ss_flags should have failed with EINVAL, "
			"got %s\n", strerror(errno));
	errno = 0;
	T(sigaltstack(0, 0));

	return t_status;
}
