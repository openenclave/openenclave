#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include "test.h"

#define TEST(r, f, x, m) ( \
	((r) = (f)) == (x) || (t_error("%s failed (" m ")\n", #f, r, x), 0) )

#define TEST_E(f) ( \
	(errno = 0), \
	(f) || (t_error("%s failed (errno = %d)\n", #f, errno), 0) )

#define TEST_S(s, x, m) ( \
	!strcmp((s),(x)) || \
		(t_error("[%s] != [%s] (%s)\n", s, x, m), 0) )

static sig_atomic_t got_sig;

static void handler(int sig) {
	got_sig = 1;
}

int main(void)
{
	int i;
	char foo[6];
	char cmd[64];
	FILE *f;

	TEST_E(f = popen("echo hello", "r"));
	if (f) {
		TEST_E(fgets(foo, sizeof foo, f));
		TEST_S(foo, "hello", "child process did not say hello");
		TEST(i, pclose(f), 0, "exit status %04x != %04x");
	}

	signal(SIGUSR1, handler);
	snprintf(cmd, sizeof cmd, "read a ; test \"x$a\" = xhello && kill -USR1 %d", getpid());
	TEST_E(f = popen(cmd, "w"));
	if (f) {
		TEST_E(fputs("hello", f) >= 0);
		TEST(i, pclose(f), 0, "exit status %04x != %04x");
		TEST(i, got_sig, 1, "child process did not send signal");
	}
	signal(SIGUSR1, SIG_DFL);
	return t_status;
}
