// by Jens Gustedt from http://www.openwall.com/lists/musl/2014/08/11/1
// c11 threads test was removed and t_error messages were added
// the test deadlocks with a broken cond var implementation so
// cond_waits were changed to cond_timedwaits with short timeout
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include "test.h"

# include <pthread.h>

# define VERSION "POSIX threads"

typedef pthread_mutex_t mutex;
typedef pthread_cond_t condition;
typedef pthread_t thread;
typedef void* thread_ret;

# define mutex_init(M) pthread_mutex_init((M), 0)
# define mutex_destroy pthread_mutex_destroy
# define mutex_lock pthread_mutex_lock
# define mutex_unlock pthread_mutex_unlock

# define condition_init(C) pthread_cond_init((C), 0)
# define condition_destroy pthread_cond_destroy
# define condition_wait pthread_cond_wait
# define condition_timedwait pthread_cond_timedwait
# define condition_signal pthread_cond_signal
# define condition_broadcast pthread_cond_broadcast


# define thread_create(ID, START, ARG) pthread_create(ID, 0, START, ARG)
# define thread_join pthread_join

# define gettime(TS) clock_gettime(CLOCK_REALTIME, (TS))

# define errorstring strerror

#ifdef __GLIBC__
# define LIBRARY "glibc"
#else
# define LIBRARY "unidentified"
#endif

#define trace2(L, ...) fprintf(stderr, __FILE__ ":" #L ": " __VA_ARGS__)
#define trace1(L, ...) trace2(L, __VA_ARGS__)
#ifdef DEBUG
# define trace(...) trace1(__LINE__, __VA_ARGS__)
#else
# define trace(...) do { if (0) trace1(__LINE__, __VA_ARGS__); } while (0)
#endif

//#define tell(...) trace1(__LINE__, __VA_ARGS__)
#define tell(...) trace(__VA_ARGS__)

enum {
  phases = 10,
  threads = 10,
};

static thread id[threads];
static unsigned args[threads];

static mutex mut[phases];
static unsigned inside[phases];

static condition cond_client;
static condition cond_main;
static unsigned volatile phase;

static void settimeout(struct timespec *ts)
{
  if (clock_gettime(CLOCK_REALTIME, ts))
    t_error("clock_gettime failed: %s\n", strerror(errno));
  ts->tv_nsec += 500*1000*1000;
  if (ts->tv_nsec >= 1000*1000*1000) {
    ts->tv_nsec -= 1000*1000*1000;
    ts->tv_sec++;
  }
}

static thread_ret client(void *arg) {
  struct timespec ts;
  unsigned * number = arg;
  for (unsigned i = 0; i < phases; ++i) {
    trace("thread %u in phase %u\n", *number, i);
    mutex_lock(&mut[i]);
    ++inside[i];
    if (inside[i] == threads) {
      trace("thread %u is last, signalling main\n", *number);
      int ret = condition_signal(&cond_main);
      trace("thread %u is last, signalling main, %s\n", *number, errorstring(ret));
      if (ret)
        t_error("thread %u is last in phase %u, signalling main failed: %s\n", *number, i, errorstring(ret));
    }
    while (i == phase) {
      tell("thread %u in phase %u (%u), waiting\n", *number, i, phase);
      settimeout(&ts);
      int ret = condition_timedwait(&cond_client, &mut[i], &ts);
      trace("thread %u in phase %u (%u), finished, %s\n", *number, i, phase, errorstring(ret));
      if (ret) {
        t_error("thread %u in phase %u (%u) finished waiting: %s\n", *number, i, phase, errorstring(ret));
        exit(t_status);
      }
    }
    int ret = mutex_unlock(&mut[i]);
    trace("thread %u in phase %u (%u), has unlocked mutex: %s\n", *number, i, phase, errorstring(ret));
    if (ret)
      t_error("thread %u in phase %u (%u), failed to unlock: %s\n", *number, i, phase, errorstring(ret));
  }
  return 0;
}


int main(void) {
  struct timespec ts;

  tell("start up of main, using %s, library %s\n", VERSION, LIBRARY);
  condition_init(&cond_client);
  condition_init(&cond_main);
  for (unsigned i = 0; i < phases; ++i) {
    mutex_init(&mut[i]);
  }
  mutex_lock(&mut[0]);

  for (unsigned i = 0; i < threads; ++i) {
    args[i] = i;
    thread_create(&id[i], client, &args[i]);
  }

  while (phase < phases) {
    while (inside[phase] < threads) {
      trace("main seeing %u threads in phase %u, waiting\n", inside[phase], phase);
      settimeout(&ts);
      int ret = condition_timedwait(&cond_main, &mut[phase], &ts);
      tell("main seeing %u threads in phase %u, %s\n", inside[phase], phase, errorstring(ret));
      if (ret) {
        t_error("main thread in phase %u (%u threads inside), finished waiting: %s\n", phase, inside[phase], errorstring(ret));
        return t_status;
      }
    }
    /* now we know that everybody is waiting inside, lock the next
       mutex, if any, such that nobody can enter the next phase
       without our permission. */
    if (phase < phases-1)
      mutex_lock(&mut[phase+1]);
    /* Now signal all clients, update the phase count and release the
       mutex they are waiting for. */
    int ret = condition_broadcast(&cond_client);
    trace("main has broadcast to %u: %s\n", phase, errorstring(ret));
    if (ret)
      t_error("main broadcast in phase %u failed: %s\n", phase, errorstring(ret));
    ++phase;
    ret = mutex_unlock(&mut[phase-1]);
    trace("main has unlocked mutex %u: %s\n", phase-1, errorstring(ret));
    if (ret)
      t_error("main failed to unlock mutex %u: %s\n", phase-1, errorstring(ret));
  }



  trace("main finished loop\n");

  for (unsigned i = 0; i < threads; ++i) {
    trace("main joining thread %u\n", i);
    int ret = thread_join(id[i], &(thread_ret){0});
    trace("main joining thread %u: %s\n", i, errorstring(ret));
    if (ret)
      t_error("main failed join thread %u: %s\n", i, errorstring(ret));
  }

  /* C functions to destroy the control structures don't return error
     information, so we can't check for errors, here. */
  for (unsigned i = 0; i < phases; ++i) {
    mutex_destroy(&mut[i]);
  }
  condition_destroy(&cond_main);
  condition_destroy(&cond_client);

  tell("shut down of main, using %s, library %s\n", VERSION, LIBRARY);

  return t_status;
}
