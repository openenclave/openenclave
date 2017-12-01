#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define TEST(c, ...) ( (c) || (t_error(#c " failed: " __VA_ARGS__),0) )

static int w(pid_t pid)
{
	int r, s;
	r = waitpid(pid, &s, 0);
	if (r == -1)
		t_error("waitpid failed: %s\n", strerror(errno));
	else if (r != pid)
		t_error("child pid was %d, waitpid returned %d\n", pid, r);
	else
		return s;
	return -1;
}

static void test_exit(int code)
{
	pid_t pid;
	if((pid = vfork()) == 0) {
		_exit(code);
		t_error("exit failed: %s\n", strerror(errno));
	}
	if (pid == -1) {
		t_error("vfork failed: %s\n", strerror(errno));
		return;
	}
	int r = w(pid);
	TEST(WIFEXITED(r), "child terminated abnormally\n");
	TEST(WEXITSTATUS(r) == code, "child exited with %d, expected %d\n", WEXITSTATUS(r), code);
}

static int sh(const char *cmd)
{
	pid_t pid;
	if((pid = vfork()) == 0) {
		execl("/bin/sh", "/bin/sh", "-c", cmd, (char*)0);
		t_error("execl failed: %s\n", strerror(errno));
		_exit(1);
	}
	if (pid == -1) {
		t_error("vfork failed: %s\n", strerror(errno));
		return -1;
	}
	return w(pid);
}

static void test_shell_exit(const char *cmd, int code)
{
	int r = sh(cmd);
	TEST(WIFEXITED(r), "child terminated abnormally\n");
	TEST(WEXITSTATUS(r) == code, "child exited with %d, expected %d\n", WEXITSTATUS(r), code);
}

static void test_shell_kill(const char *cmd, int sig)
{
	int r = sh(cmd);
	TEST(WIFSIGNALED(r), "child did not get killed\n");
	TEST(WTERMSIG(r) == sig, "child is killed by %d, expected %d\n", WTERMSIG(r), sig);
}

int main() {
	test_exit(0);
	test_exit(1);
	test_shell_exit("exit 0", 0);
	test_shell_exit("exit 1", 1);
	test_shell_kill("kill -9 $$", 9);
	return t_status;
}
