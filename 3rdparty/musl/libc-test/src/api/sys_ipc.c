#include <sys/ipc.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(uid_t)
T(gid_t)
T(mode_t)
T(key_t)
{
struct ipc_perm x;
F(uid_t,uid)
F(gid_t,gid)
F(uid_t,cuid)
F(gid_t,cgid)
F(mode_t, mode)
}
C(IPC_CREAT)
C(IPC_EXCL)
C(IPC_NOWAIT)
C(IPC_PRIVATE)
C(IPC_RMID)
C(IPC_SET)
C(IPC_STAT)
{key_t(*p)(const char*,int) = ftok;}
}
