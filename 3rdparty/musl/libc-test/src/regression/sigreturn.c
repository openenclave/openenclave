// commit: dc3776d445957cd3ea4a682db518701b93d34292 2011-02-13
// sigreturn crash
#include <signal.h>

static volatile sig_atomic_t x;

void handler(int s)
{
	x = 1;
}

int main(void)
{
	signal(SIGINT, handler);
	if (raise(SIGINT))
		return 2;
	if (x != 1)
		return 1;
	return 0;
}
