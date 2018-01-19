#include <sys/shm.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(shmatt_t)
T(pid_t)
T(size_t)
T(time_t)
C(SHM_RDONLY)
C(SHM_RND)
C(SHMLBA)
{
struct shmid_ds x;
F(struct ipc_perm, shm_perm)
F(size_t,shm_segsz)
F(pid_t, shm_lpid)
F(pid_t, shm_cpid)
F(shmatt_t,shm_nattch)
F(time_t,shm_atime)
F(time_t,shm_dtime)
F(time_t,shm_ctime)
}
{void*(*p)(int,const void*,int) = shmat;}
{int(*p)(int,int,struct shmid_ds*) = shmctl;}
{int(*p)(const void*) = shmdt;}
{int(*p)(key_t,size_t,int) = shmget;}

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
