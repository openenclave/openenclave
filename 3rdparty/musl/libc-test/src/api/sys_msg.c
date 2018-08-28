#include <sys/msg.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(msgqnum_t)
T(msglen_t)
T(pid_t)
T(size_t)
T(ssize_t)
T(time_t)
C(MSG_NOERROR)
{
struct msqid_ds x;
F(struct ipc_perm, msg_perm)
F(msgqnum_t, msg_qnum)
F(msglen_t,msg_qbytes)
F(pid_t, msg_lspid)
F(pid_t, msg_lrpid)
F(time_t, msg_stime)
F(time_t, msg_rtime)
F(time_t,msg_ctime)
}
{int(*p)(int,int,struct msqid_ds*) = msgctl;}
{int(*p)(key_t,int) = msgget;}
{ssize_t(*p)(int,void*,size_t,long,int) = msgrcv;}
{int(*p)(int,const void*,size_t,int) = msgsnd;}
}
