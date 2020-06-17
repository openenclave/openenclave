#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <unistd.h>
#include "test.h"

static const char path[] = ".";
static const int id = 's';

#define T(f) do{ \
	if ((f)+1 == 0) \
		t_error("%s failed: %s\n", #f, strerror(errno)); \
}while(0)

#define EQ(a,b,fmt) do{ \
	if ((a) != (b)) \
		t_error("%s == %s failed: " fmt "\n", #a, #b, a, b); \
}while(0)

static void inc()
{
	time_t t;
	key_t k;
	int semid, semval, sempid, semncnt, semzcnt;
	struct semid_ds semid_ds;
	union semun {
		int val;
		struct semid_ds *buf;
		unsigned short *array;
	} arg;
	struct sembuf sops;

	T(t = time(0));
	T(k = ftok(path, id));

	/* make sure we get a clean semaphore id */
	T(semid = semget(k, 1, IPC_CREAT|0666));
	T(semctl(semid, 0, IPC_RMID));
	T(semid = semget(k, 1, IPC_CREAT|IPC_EXCL|0666));

	if (t_status)
		exit(t_status);

	/* check IPC_EXCL */
	errno = 0;
	if (semget(k, 1, IPC_CREAT|IPC_EXCL|0666) != -1 || errno != EEXIST)
		t_error("semget(IPC_CREAT|IPC_EXCL) should have failed with EEXIST, got %s\n", strerror(errno));

	/* check if msgget initilaized the msqid_ds structure correctly */
	arg.buf = &semid_ds;
	T(semctl(semid, 0, IPC_STAT, arg));
	EQ(semid_ds.sem_perm.cuid, geteuid(), "got %d, want %d");
	EQ(semid_ds.sem_perm.uid, geteuid(), "got %d, want %d");
	EQ(semid_ds.sem_perm.cgid, getegid(), "got %d, want %d");
	EQ(semid_ds.sem_perm.gid, getegid(), "got %d, want %d");
	EQ(semid_ds.sem_perm.mode & 0x1ff, 0666, "got %o, want %o");
	EQ(semid_ds.sem_nsems, 1, "got %d, want %d");
	EQ((long long)semid_ds.sem_otime, 0, "got %lld, want %d");
	if (semid_ds.sem_ctime < t)
		t_error("semid_ds.sem_ctime >= t failed: got %lld, want >= %lld\n", (long long)semid_ds.sem_ctime, (long long)t);
	if (semid_ds.sem_ctime > t+5)
		t_error("semid_ds.sem_ctime <= t+5 failed: got %lld, want <= %lld\n", (long long)semid_ds.sem_ctime, (long long)t+5);

	/* test sem_op > 0 */
	sops.sem_num = 0;
	sops.sem_op = 1;
	sops.sem_flg = 0;
	T(semop(semid, &sops, 1));
	T(semval = semctl(semid, 0, GETVAL));
	EQ(semval, 1, "got %d, want %d");
	T(sempid = semctl(semid, 0, GETPID));
	EQ(sempid, getpid(), "got %d, want %d");
	T(semncnt = semctl(semid, 0, GETNCNT));
	EQ(semncnt, 0, "got %d, want %d");
	T(semzcnt = semctl(semid, 0, GETZCNT));
	EQ(semzcnt, 0, "got %d, want %d");
}

static void dec()
{
	key_t k;
	int semid, semval;
	struct sembuf sops;

	T(k = ftok(path, id));
	T(semid = semget(k, 0, 0));

	/* test sem_op < 0 */
	sops.sem_num = 0;
	sops.sem_op = -1;
	sops.sem_flg = 0;
	T(semop(semid, &sops, 1));
	T(semval = semctl(semid, 0, GETVAL));
	EQ(semval, 0, "got %d, want %d");

	/* cleanup */
	T(semctl(semid, 0, IPC_RMID));
}

int main(void)
{
	int p;
	int status;

	inc();
	p = fork();
	if (p == -1)
		t_error("fork failed: %s\n", strerror(errno));
	else if (p == 0)
		dec();
	else {
		T(waitpid(p, &status, 0));
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			t_error("child exit status: %d\n", status);
	}
	return t_status;
}

