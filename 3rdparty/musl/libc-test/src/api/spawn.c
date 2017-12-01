#include <spawn.h>
#include "options.h"
#define T(t) (t*)0;
#define C(n) switch(n){case n:;}
static void f()
{
T(posix_spawnattr_t)
T(posix_spawn_file_actions_t)
T(mode_t)
T(pid_t)
T(sigset_t)
T(struct sched_param)
C(POSIX_SPAWN_RESETIDS)
C(POSIX_SPAWN_SETPGROUP)
#ifdef POSIX_PRIORITY_SCHEDULING
C(POSIX_SPAWN_SETSCHEDPARAM)
C(POSIX_SPAWN_SETSCHEDULER)
#endif
C(POSIX_SPAWN_SETSIGDEF)
C(POSIX_SPAWN_SETSIGMASK)
{int(*p)(pid_t*restrict,const char*restrict,const posix_spawn_file_actions_t*,const posix_spawnattr_t*restrict,char*const[restrict],char*const[restrict]) = posix_spawn;}
{int(*p)(posix_spawn_file_actions_t*,int) = posix_spawn_file_actions_addclose;}
{int(*p)(posix_spawn_file_actions_t*,int,int) = posix_spawn_file_actions_adddup2;}
{int(*p)(posix_spawn_file_actions_t*restrict,int,const char*restrict,int,mode_t) = posix_spawn_file_actions_addopen;}
{int(*p)(posix_spawn_file_actions_t*) = posix_spawn_file_actions_destroy;}
{int(*p)(posix_spawn_file_actions_t*) = posix_spawn_file_actions_init;}
{int(*p)(posix_spawnattr_t*) = posix_spawnattr_destroy;}
{int(*p)(const posix_spawnattr_t*restrict,short*restrict) = posix_spawnattr_getflags;}
{int(*p)(const posix_spawnattr_t*restrict,pid_t*restrict) = posix_spawnattr_getpgroup;}
{int(*p)(posix_spawnattr_t*) = posix_spawnattr_init;}
{int(*p)(posix_spawnattr_t*,short) = posix_spawnattr_setflags;}
{int(*p)(posix_spawnattr_t*,pid_t) = posix_spawnattr_setpgroup;}
{int(*p)(pid_t*restrict,const char*restrict,const posix_spawn_file_actions_t*,const posix_spawnattr_t*restrict,char*const[restrict],char*const[restrict]) = posix_spawnp;}
}
#include <signal.h>
static void g()
{
{int(*p)(const posix_spawnattr_t*restrict,sigset_t*restrict) = posix_spawnattr_getsigdefault;}
{int(*p)(const posix_spawnattr_t*restrict,sigset_t*restrict) = posix_spawnattr_getsigmask;}
{int(*p)(posix_spawnattr_t*restrict,const sigset_t*restrict) = posix_spawnattr_setsigdefault;}
{int(*p)(posix_spawnattr_t*restrict,const sigset_t*restrict) = posix_spawnattr_setsigmask;}
}
#ifdef POSIX_PRIORITY_SCHEDULING
#include <sched.h>
static void h()
{
{int(*p)(const posix_spawnattr_t*restrict,struct sched_param*restrict) = posix_spawnattr_getschedparam;}
{int(*p)(const posix_spawnattr_t*restrict,int*restrict) = posix_spawnattr_getschedpolicy;}
{int(*p)(posix_spawnattr_t*restrict,const struct sched_param*restrict) = posix_spawnattr_setschedparam;}
{int(*p)(posix_spawnattr_t*,int) = posix_spawnattr_setschedpolicy;}
}
#endif
