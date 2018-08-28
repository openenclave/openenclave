#include <sys/wait.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(id_t)
T(pid_t)
T(siginfo_t)
C(WEXITSTATUS(0))
C(WIFEXITED(0))
C(WIFSIGNALED(0))
C(WIFSTOPPED(0))
C(WNOHANG)
C(WSTOPSIG(0))
C(WTERMSIG(0))
C(WUNTRACED)
#ifdef _XOPEN_SOURCE
C(WCONTINUED)
C(WIFCONTINUED(0))
#endif
C(WEXITED)
C(WNOWAIT)
C(WSTOPPED)
{idtype_t x = P_ALL;}
{idtype_t x = P_PGID;}
{idtype_t x = P_PID;}
{pid_t(*p)(int*) = wait;}
{int(*p)(idtype_t,id_t,siginfo_t*,int) = waitid;}
{pid_t(*p)(pid_t,int*,int) = waitpid;}
}
