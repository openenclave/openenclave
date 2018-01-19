#include <sys/sem.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(pid_t)
T(size_t)
T(time_t)
C(SEM_UNDO)
C(GETNCNT)
C(GETPID)
C(GETVAL)
C(GETALL)
C(GETZCNT)
C(SETVAL)
C(SETALL)
{
struct semid_ds x;
F(struct ipc_perm,sem_perm)
F(unsigned short, sem_nsems)
F(time_t, sem_otime)
F(time_t, sem_ctime)
}
{
struct sembuf x;
F(unsigned short,sem_num)
F(short, sem_op)
F(short, sem_flg)
}
{int(*p)(int,int,int,...) = semctl;}
{int(*p)(key_t,int,int) = semget;}
{int(*p)(int,struct sembuf*,size_t) = semop;}

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
