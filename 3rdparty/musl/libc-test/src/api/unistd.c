#include <unistd.h>
#include "options.h"
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
#define A(n) {char p[n];}
static void f()
{
A(_POSIX_VERSION >= 200809L)
A(_POSIX2_VERSION >= 200809L)
#ifdef _XOPEN_SOURCE
A(_XOPEN_VERSION >= 700)
// A(_XOPEN_CRYPT >= 0)
 A(_XOPEN_ENH_I18N > 0)
// A(_XOPEN_REALTIME >= 0)
// A(_XOPEN_REALTIME_THREADS >= 0)
// A(_XOPEN_SHM >= 0)
 A(_XOPEN_UNIX >= 0)
#endif
A(_POSIX_ASYNCHRONOUS_IO >= 200809L)
A(_POSIX_BARRIERS >= 200809L)
A(_POSIX_CHOWN_RESTRICTED >= 0)
A(_POSIX_CLOCK_SELECTION >= 200809L)
A(_POSIX_JOB_CONTROL > 0)
A(_POSIX_MAPPED_FILES >= 200809L)
A(_POSIX_MEMORY_PROTECTION >= 200809L)
A(_POSIX_NO_TRUNC >= 0)
A(_POSIX_READER_WRITER_LOCKS >= 200809L)
A(_POSIX_REALTIME_SIGNALS >= 200809L)
A(_POSIX_REGEXP > 0)
A(_POSIX_SAVED_IDS > 0)
A(_POSIX_SEMAPHORES >= 200809L)
A(_POSIX_SHELL > 0)
A(_POSIX_SPIN_LOCKS >= 200809L)
A(_POSIX_THREAD_SAFE_FUNCTIONS >= 200809L)
A(_POSIX_THREADS >= 200809L)
A(_POSIX_TIMEOUTS >= 200809L)
A(_POSIX_TIMERS >= 200809L)
#if _POSIX_V7_ILP32_OFFBIG<=0 && _POSIX_V7_LP64_OFF64<=0 && _POSIX_V7_LPBIG_OFFBIG<=0
#error _POSIX_V7_ILP32_OFFBIG<=0 && _POSIX_V7_LP64_OFF64<=0 && _POSIX_V7_LPBIG_OFFBIG<=0
#endif
A(_POSIX2_C_BIND >= 200809L)
// not required by the standard
 A(_POSIX_ADVISORY_INFO >= 0)
 A(_POSIX_CPUTIME >= 0)
 A(_POSIX_FSYNC >= 0)
 A(_POSIX_IPV6 >= 0)
 A(_POSIX_MEMLOCK >= 0)
 A(_POSIX_MEMLOCK_RANGE >= 0)
 A(_POSIX_MESSAGE_PASSING >= 0)
 A(_POSIX_MONOTONIC_CLOCK >= 0)
// A(_POSIX_PRIORITIZED_IO >= 0)
// A(_POSIX_PRIORITY_SCHEDULING >= 0)
 A(_POSIX_RAW_SOCKETS >= 0)
// A(_POSIX_SHARED_MEMORY_OBJECTS >= 0)
 A(_POSIX_SPAWN >= 0)
// A(_POSIX_SPORADIC_SERVER >= 0)
// A(_POSIX_SYNCHRONIZED_IO >= 0)
 A(_POSIX_THREAD_ATTR_STACKADDR >= 0)
 A(_POSIX_THREAD_ATTR_STACKSIZE >= 0)
 A(_POSIX_THREAD_CPUTIME >= 0)
// A(_POSIX_THREAD_PRIO_INHERIT >= 0)
// A(_POSIX_THREAD_PRIO_PROTECT >= 0)
 A(_POSIX_THREAD_PRIORITY_SCHEDULING >= 0)
 A(_POSIX_THREAD_PROCESS_SHARED >= 0)
// A(_POSIX_THREAD_ROBUST_PRIO_INHERIT >= 0)
// A(_POSIX_THREAD_ROBUST_PRIO_PROTECT >= 0)
// A(_POSIX_THREAD_SPORADIC_SERVER >= 0)
// A(_POSIX_TYPED_MEMORY_OBJECTS >= 0)
C(F_OK)
C(R_OK)
C(W_OK)
C(X_OK)
C(_CS_PATH)
C(_CS_POSIX_V7_ILP32_OFF32_CFLAGS)
C(_CS_POSIX_V7_ILP32_OFF32_LDFLAGS)
C(_CS_POSIX_V7_ILP32_OFF32_LIBS)
C(_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS)
C(_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS)
C(_CS_POSIX_V7_ILP32_OFFBIG_LIBS)
C(_CS_POSIX_V7_LP64_OFF64_CFLAGS)
C(_CS_POSIX_V7_LP64_OFF64_LDFLAGS)
C(_CS_POSIX_V7_LP64_OFF64_LIBS)
C(_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS)
C(_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS)
C(_CS_POSIX_V7_LPBIG_OFFBIG_LIBS)
C(_CS_POSIX_V7_THREADS_CFLAGS)
C(_CS_POSIX_V7_THREADS_LDFLAGS)
C(_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS)
C(_CS_V7_ENV)
C(SEEK_CUR)
C(SEEK_END)
C(SEEK_SET)
C(F_LOCK)
C(F_TEST)
C(F_TLOCK)
C(F_ULOCK)
C(_PC_2_SYMLINKS)
C(_PC_ALLOC_SIZE_MIN)
C(_PC_ASYNC_IO)
C(_PC_CHOWN_RESTRICTED)
C(_PC_FILESIZEBITS)
C(_PC_LINK_MAX)
C(_PC_MAX_CANON)
C(_PC_MAX_INPUT)
C(_PC_NAME_MAX)
C(_PC_NO_TRUNC)
C(_PC_PATH_MAX)
C(_PC_PIPE_BUF)
C(_PC_PRIO_IO)
C(_PC_REC_INCR_XFER_SIZE)
C(_PC_REC_MAX_XFER_SIZE)
C(_PC_REC_MIN_XFER_SIZE)
C(_PC_REC_XFER_ALIGN)
C(_PC_SYMLINK_MAX)
C(_PC_SYNC_IO)
C(_PC_TIMESTAMP_RESOLUTION)
C(_PC_VDISABLE)
C(_SC_2_C_BIND)
C(_SC_2_C_DEV)
C(_SC_2_CHAR_TERM)
C(_SC_2_FORT_DEV)
C(_SC_2_FORT_RUN)
C(_SC_2_LOCALEDEF)
C(_SC_2_PBS)
C(_SC_2_PBS_ACCOUNTING)
C(_SC_2_PBS_CHECKPOINT)
C(_SC_2_PBS_LOCATE)
C(_SC_2_PBS_MESSAGE)
C(_SC_2_PBS_TRACK)
C(_SC_2_SW_DEV)
C(_SC_2_UPE)
C(_SC_2_VERSION)
C(_SC_ADVISORY_INFO)
C(_SC_AIO_LISTIO_MAX)
C(_SC_AIO_MAX)
C(_SC_AIO_PRIO_DELTA_MAX)
C(_SC_ARG_MAX)
C(_SC_ASYNCHRONOUS_IO)
C(_SC_ATEXIT_MAX)
C(_SC_BARRIERS)
C(_SC_BC_BASE_MAX)
C(_SC_BC_DIM_MAX)
C(_SC_BC_SCALE_MAX)
C(_SC_BC_STRING_MAX)
C(_SC_CHILD_MAX)
C(_SC_CLK_TCK)
C(_SC_CLOCK_SELECTION)
C(_SC_COLL_WEIGHTS_MAX)
C(_SC_CPUTIME)
C(_SC_DELAYTIMER_MAX)
C(_SC_EXPR_NEST_MAX)
C(_SC_FSYNC)
C(_SC_GETGR_R_SIZE_MAX)
C(_SC_GETPW_R_SIZE_MAX)
C(_SC_HOST_NAME_MAX)
C(_SC_IOV_MAX)
C(_SC_IPV6)
C(_SC_JOB_CONTROL)
C(_SC_LINE_MAX)
C(_SC_LOGIN_NAME_MAX)
C(_SC_MAPPED_FILES)
C(_SC_MEMLOCK)
C(_SC_MEMLOCK_RANGE)
C(_SC_MEMORY_PROTECTION)
C(_SC_MESSAGE_PASSING)
C(_SC_MONOTONIC_CLOCK)
C(_SC_MQ_OPEN_MAX)
C(_SC_MQ_PRIO_MAX)
C(_SC_NGROUPS_MAX)
C(_SC_OPEN_MAX)
C(_SC_PAGE_SIZE)
C(_SC_PAGESIZE)
C(_SC_PRIORITIZED_IO)
C(_SC_PRIORITY_SCHEDULING)
C(_SC_RAW_SOCKETS)
C(_SC_RE_DUP_MAX)
C(_SC_READER_WRITER_LOCKS)
C(_SC_REALTIME_SIGNALS)
C(_SC_REGEXP)
C(_SC_RTSIG_MAX)
C(_SC_SAVED_IDS)
C(_SC_SEM_NSEMS_MAX)
C(_SC_SEM_VALUE_MAX)
C(_SC_SEMAPHORES)
C(_SC_SHARED_MEMORY_OBJECTS)
C(_SC_SHELL)
C(_SC_SIGQUEUE_MAX)
C(_SC_SPAWN)
C(_SC_SPIN_LOCKS)
C(_SC_SPORADIC_SERVER)
C(_SC_SS_REPL_MAX)
C(_SC_STREAM_MAX)
C(_SC_SYMLOOP_MAX)
C(_SC_SYNCHRONIZED_IO)
C(_SC_THREAD_ATTR_STACKADDR)
C(_SC_THREAD_ATTR_STACKSIZE)
C(_SC_THREAD_CPUTIME)
C(_SC_THREAD_DESTRUCTOR_ITERATIONS)
C(_SC_THREAD_KEYS_MAX)
C(_SC_THREAD_PRIO_INHERIT)
C(_SC_THREAD_PRIO_PROTECT)
C(_SC_THREAD_PRIORITY_SCHEDULING)
C(_SC_THREAD_PROCESS_SHARED)
C(_SC_THREAD_ROBUST_PRIO_INHERIT)
C(_SC_THREAD_ROBUST_PRIO_PROTECT)
C(_SC_THREAD_SAFE_FUNCTIONS)
C(_SC_THREAD_SPORADIC_SERVER)
C(_SC_THREAD_STACK_MIN)
C(_SC_THREAD_THREADS_MAX)
C(_SC_THREADS)
C(_SC_TIMEOUTS)
C(_SC_TIMER_MAX)
C(_SC_TIMERS)
C(_SC_TRACE)
C(_SC_TRACE_EVENT_FILTER)
C(_SC_TRACE_EVENT_NAME_MAX)
C(_SC_TRACE_INHERIT)
C(_SC_TRACE_LOG)
C(_SC_TRACE_NAME_MAX)
C(_SC_TRACE_SYS_MAX)
C(_SC_TRACE_USER_EVENT_MAX)
C(_SC_TTY_NAME_MAX)
C(_SC_TYPED_MEMORY_OBJECTS)
C(_SC_TZNAME_MAX)
C(_SC_V7_ILP32_OFF32)
C(_SC_V7_ILP32_OFFBIG)
C(_SC_V7_LP64_OFF64)
C(_SC_V7_LPBIG_OFFBIG)
C(_SC_VERSION)
C(_SC_XOPEN_CRYPT)
C(_SC_XOPEN_ENH_I18N)
C(_SC_XOPEN_REALTIME)
C(_SC_XOPEN_REALTIME_THREADS)
C(_SC_XOPEN_SHM)
C(_SC_XOPEN_STREAMS)
C(_SC_XOPEN_UNIX)
C(_SC_XOPEN_UUCP)
C(_SC_XOPEN_VERSION)
C(STDERR_FILENO)
C(STDIN_FILENO)
C(STDOUT_FILENO)
C(_POSIX_VDISABLE)
T(size_t)
T(ssize_t)
T(uid_t)
T(gid_t)
T(off_t)
T(pid_t)
T(intptr_t)
{void(*p)(int) = _exit;}
{int(*p)(const char*,int) = access;}
{unsigned(*p)(unsigned) = alarm;}
{int(*p)(const char*) = chdir;}
{int(*p)(const char*,uid_t,gid_t) = chown;}
{int(*p)(int) = close;}
{size_t(*p)(int,char*,size_t) = confstr;}
{int(*p)(int) = dup;}
{int(*p)(int,int) = dup2;}
{extern char **environ; char **x = environ;};
{int(*p)(const char*,const char*,...) = execl;}
{int(*p)(const char*,const char*,...) = execle;}
{int(*p)(const char*,const char*,...) = execlp;}
{int(*p)(const char*,char*const[]) = execv;}
{int(*p)(const char*,char*const[],char*const[]) = execve;}
{int(*p)(const char*,char*const[]) = execvp;}
{int(*p)(int,const char*,int,int) = faccessat;}
{int(*p)(int) = fchdir;}
{int(*p)(int,uid_t,gid_t) = fchown;}
{int(*p)(int,const char*,uid_t,gid_t,int) = fchownat;}
#ifdef POSIX_SYNCHRONIZED_IO
{int(*p)(int) = fdatasync;}
#endif
{int(*p)(int,char*const[],char*const[]) = fexecve;}
{pid_t(*p)(void) = fork;}
{long(*p)(int,int) = fpathconf;}
{int(*p)(int) = fsync;}
{int(*p)(int,off_t) = ftruncate;}
{char*(*p)(char*,size_t) = getcwd;}
{gid_t(*p)(void) = getegid;}
{uid_t(*p)(void) = geteuid;}
{gid_t(*p)(void) = getgid;}
{int(*p)(int,gid_t[]) = getgroups;}
{int(*p)(char*,size_t) = gethostname;}
{char*(*p)(void) = getlogin;}
{int(*p)(char*,size_t) = getlogin_r;}
{int(*p)(int,char*const[],const char*) = getopt;}
{pid_t(*p)(pid_t) = getpgid;}
{pid_t(*p)(void) = getpgrp;}
{pid_t(*p)(void) = getpid;}
{pid_t(*p)(void) = getppid;}
{pid_t(*p)(pid_t) = getsid;}
{uid_t(*p)(void) = getuid;}
{int(*p)(int) = isatty;}
{int(*p)(const char*,uid_t,gid_t) = lchown;}
{int(*p)(const char*,const char*) = link;}
{int(*p)(int,const char*,int,const char*,int) = linkat;}
{off_t(*p)(int,off_t,int) = lseek;}
{char *x = optarg;}
{int i = opterr;}
{int i = optind;}
{int i = optopt;}
{long(*p)(const char*,int) = pathconf;}
{int(*p)(void) = pause;}
{int(*p)(int[]) = pipe;}
{ssize_t(*p)(int,void*,size_t,off_t) = pread;}
{ssize_t(*p)(int,const void*,size_t,off_t) = pwrite;}
{ssize_t(*p)(int,void*,size_t) = read;}
{ssize_t(*p)(const char*restrict,char*restrict,size_t) = readlink;}
{ssize_t(*p)(int,const char*restrict,char*restrict,size_t) = readlinkat;}
{int(*p)(const char*) = rmdir;}
{int(*p)(gid_t) = setegid;}
{int(*p)(uid_t) = seteuid;}
{int(*p)(gid_t) = setgid;}
{int(*p)(pid_t,pid_t) = setpgid;}
{pid_t(*p)(void) = setsid;}
{int(*p)(uid_t) = setuid;}
{unsigned(*p)(unsigned) = sleep;}
{int(*p)(const char*,const char*) = symlink;}
{int(*p)(const char*,int,const char*) = symlinkat;}
{long(*p)(int) = sysconf;}
{pid_t(*p)(int) = tcgetpgrp;}
{int(*p)(int,pid_t) = tcsetpgrp;}
{int(*p)(const char*,off_t) = truncate;}
{char*(*p)(int) = ttyname;}
{int(*p)(int,char*,size_t) = ttyname_r;}
{int(*p)(const char*) = unlink;}
{int(*p)(int,const char*,int) = unlinkat;}
{ssize_t(*p)(int,const void*,size_t) = write;}
#ifdef _XOPEN_SOURCE
{char*(*p)(const char*,const char*) = crypt;}
{void(*p)(char[],int) = encrypt;}
{long(*p)(void) = gethostid;}
{int(*p)(int,int,off_t) = lockf;}
{int(*p)(int) = nice;}
{int(*p)(gid_t,gid_t) = setregid;}
{int(*p)(uid_t,uid_t) = setreuid;}
{void(*p)(const void*restrict,void*restrict,ssize_t) = swab;}
{void(*p)(void) = sync;}
#endif
}
