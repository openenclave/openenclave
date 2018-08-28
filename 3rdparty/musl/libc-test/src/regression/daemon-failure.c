// commit: 19e35c500bd2b5e6146e42705ab9b69c155a2006 2011-02-17
// commit: 187fe29d5b89644b68cade75a34257a1c32a75f6 2011-02-17
// non-standard musl specific behaviour
// daemon should not fork in case of failure of chdir or open, but
// since setsid and fork may still fail after fork this behaviour
// is not very useful
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include "test.h"

int daemon(int, int);

int main(void)
{
	int r, pid, fd[2], fdout, s;
	char c;

	r = pipe(fd);
	if (r == -1) {
		t_error("pipe failed: %s\n", strerror(errno));
		return 1;
	}
	fdout = dup(1);
	if (fdout == -1) {
		t_error("dup(1) failed: %s\n", strerror(errno));
		return 1;
	}
	r = fork();
	if (r == -1) {
		t_error("fork failed: %s\n", strerror(errno));
		return 1;
	}

	if (r == 0) {
		/* exhausting all fds makes open("/dev/null") fail in daemon */
		t_fdfill();
		pid = getpid();
		errno = 0;
		r = daemon(0, 0);
		if (dup2(fdout,1) == -1) {
			write(fdout, "ERROR:\n", 7);
			t_error("failed to dup pipe fd for communicating results: %s\n", strerror(errno));
		}
		if (r != -1)
			t_error("daemon should have failed\n");
		if (errno != EMFILE)
			t_error("daemon should have failed with %d [EMFILE] got %d [%s]\n", EMFILE, errno, strerror(errno));
		if (getpid() != pid || getppid() == 1)
			t_error("daemon forked despite failure: ppid is %d, pid is %d, old pid is %d\n",
				getppid(), getpid(), pid);
		if (write(fd[1], "1" + !t_status, 1) != 1)
			t_error("write failed: %s\n", strerror(errno));
		return t_status;
	}
	close(fd[1]);
	if (waitpid(r, &s, 0) != r)
		t_error("waitpid failed: %s\n", strerror(errno));
	else if (!WIFEXITED(s))
		t_error("child exited abnormally (signal %d)\n", WIFSIGNALED(s) ? WTERMSIG(s) : 0);
	else if (WEXITSTATUS(s))
		t_error("child exited with %d\n", WEXITSTATUS(s));
	r = read(fd[0], &c, 1);
	if (r == -1)
		t_error("read failed: %s\n", strerror(errno));
	else if (r == 0)
		t_error("read failed: child did not send its exit status\n");
	else if (c != 0)
		t_error("child failed\n");

	return t_status;
}
