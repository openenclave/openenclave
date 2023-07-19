// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* ********************************
 * Author:       Johan Hanssen Seferidis
 * License:	     MIT
 * Description:  Library providing a threading pool where you can add
 *               work. For usage, check the thpool.h file or README.md
 *
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Include to use sleep function
#if defined(__linux__)
#include <sys/prctl.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include "hostthread.h"
#include "thpool.h"

#if !defined(DISABLE_PRINT)
#define err(str) fprintf(stderr, str)
#else
#define err(str)
#endif

static volatile int threads_keepalive;

/* ========================== STRUCTURES ============================ */

/* Binary semaphore */
typedef struct bsem
{
    CRITICAL_SECTION mutex;

    CONDITION_VARIABLE cond;
    int v;
} bsem;

typedef struct _job_result
{
    // Job would allocate a memory to store any return data
    // And make return_data point to that memory
    // Caller is responsible for freeing the allocated memory
    void* return_data;
    size_t size_return_data;
    int return_code;

    int completed;
    CRITICAL_SECTION mutex;
    CONDITION_VARIABLE cond;
} job_result;

/* Job */
typedef struct job
{
    struct job* prev;                         /* pointer to previous job   */
    void (*function)(void* arg, job_result*); /* function pointer          */
    void* arg;                                /* function's argument       */
    job_result* job_result;
} job;

/* Job queue */
typedef struct jobqueue
{
    oe_mutex rwmutex; /* used for queue r/w access */
    job* front;       /* pointer to front of queue */
    job* rear;        /* pointer to rear  of queue */
    bsem* has_jobs;   /* flag as binary semaphore  */
    int len;          /* number of jobs in queue   */
} jobqueue;

/* Thread */
typedef struct thread
{
    int id;                   /* friendly id               */
    oe_thread_t pthread;      /* pointer to actual thread  */
    struct thpool_* thpool_p; /* access to thpool          */
} thread;

/* Threadpool */
typedef struct thpool_
{
    thread** threads;                 /* pointer to threads        */
    volatile int num_threads_alive;   /* threads currently alive   */
    volatile int num_threads_working; /* threads currently working */
    CRITICAL_SECTION thcount_lock;            /* used for thread count etc */
    CONDITION_VARIABLE threads_all_idle;  /* signal to thpool_wait     */
    jobqueue jobqueue;                /* job queue                 */
} thpool_;

/* ========================== PROTOTYPES ============================ */

static int thread_init(thpool_* thpool_p, struct thread** thread_p, int id);
static void* thread_do(struct thread* thread_p);
static void thread_destroy(struct thread* thread_p);

static int jobqueue_init(jobqueue* jobqueue_p);
static void jobqueue_clear(jobqueue* jobqueue_p);
static void jobqueue_push(jobqueue* jobqueue_p, struct job* newjob_p);
static struct job* jobqueue_pull(jobqueue* jobqueue_p);
static void jobqueue_destroy(jobqueue* jobqueue_p);

static void bsem_init(struct bsem* bsem_p, int value);
static void bsem_reset(struct bsem* bsem_p);
static void bsem_post(struct bsem* bsem_p);
static void bsem_post_all(struct bsem* bsem_p);
static void bsem_wait(struct bsem* bsem_p);

/* ========================== THREADPOOL ============================ */

/* Initialise thread pool */
struct thpool_* thpool_init(int num_threads)
{
    threads_keepalive = 1;

    if (num_threads < 0)
    {
        num_threads = 0;
    }

    /* Make new thread pool */
    thpool_* thpool_p;
    thpool_p = (struct thpool_*)malloc(sizeof(struct thpool_));
    if (thpool_p == NULL)
    {
        err("thpool_init(): Could not allocate memory for thread pool\n");
        return NULL;
    }
    thpool_p->num_threads_alive = 0;
    thpool_p->num_threads_working = 0;

    /* Initialise the job queue */
    if (jobqueue_init(&thpool_p->jobqueue) == -1)
    {
        err("thpool_init(): Could not allocate memory for job queue\n");
        free(thpool_p);
        return NULL;
    }

    /* Make threads in pool */
    thpool_p->threads = (struct thread**)malloc(
        (unsigned long)num_threads * sizeof(struct thread*));
    if (thpool_p->threads == NULL)
    {
        err("thpool_init(): Could not allocate memory for threads\n");
        jobqueue_destroy(&thpool_p->jobqueue);
        free(thpool_p);
        return NULL;
    }

    InitializeCriticalSection(&(thpool_p->thcount_lock));
    InitializeConditionVariable(&thpool_p->threads_all_idle);

    /* Thread init */
    int n;
    for (n = 0; n < num_threads; n++)
    {
        thread_init(thpool_p, &thpool_p->threads[n], n);
    }

    /* Wait for threads to initialize */
    while (thpool_p->num_threads_alive != num_threads)
    {
    }

    return thpool_p;
}

/* Add work to the thread pool */
int thpool_add_work(
    thpool_* thpool_p,
    void (*function_p)(void*, job_result*),
    void* arg_p,
    job_result* result)
{
    job* newjob = (struct job*)malloc(sizeof(struct job));
    if (newjob == NULL)
    {
        err("thpool_add_work(): Could not allocate memory for new job\n");
        return -1;
    }

    /* add function and argument */
    newjob->function = function_p;
    newjob->arg = arg_p;
    newjob->job_result = result;

    /* add job to queue */
    jobqueue_push(&thpool_p->jobqueue, newjob);

    return 0;
}

job_result* thpool_init_result()
{
    job_result* new_job_result = (job_result*)malloc(sizeof(job_result));

    new_job_result->return_data = NULL;
    new_job_result->size_return_data = 0;
    new_job_result->completed = 0;
    // oe_mutex_init(&new_job_result->mutex);
    InitializeCriticalSection(&new_job_result->mutex);
    InitializeConditionVariable(&new_job_result->cond);

    return new_job_result;
}

void thpool_destroy_result(job_result* result)
{
    // oe_mutex_lock(&result->mutex);
    EnterCriticalSection(&result->mutex);
    free(result->return_data);
    result->return_data = NULL;
    result->size_return_data = 0;
    result->completed = 1;
    // oe_mutex_unlock(&result->mutex);
    LeaveCriticalSection(&result->mutex);

    // oe_mutex_destroy(&result->mutex);
    CloseHandle(&result->mutex);
    CloseHandle(&result->cond);
    free(result);
}

void thpool_provide_result(
    job_result* result,
    int return_code,
    void* data,
    size_t size)
{
    // oe_mutex_lock(&result->mutex);
    EnterCriticalSection(&result->mutex);
    result->return_code = return_code;
    result->return_data = data;
    result->size_return_data = size;
    result->completed = 1;
    // oe_mutex_unlock(&result->mutex);
    LeaveCriticalSection(&result->mutex);

    WakeConditionVariable(&result->cond);
}

int thpool_consume_result(job_result* result, void** out, size_t* out_size)
{
    // oe_mutex_lock(&result->mutex);
    EnterCriticalSection(&result->mutex);
    while (!result->completed)
    {
        SleepConditionVariableCS(&result->cond, &result->mutex, INFINITE);
    }

    int return_code = result->return_code;
    if (out != NULL && out_size != NULL)
    {
        *out = result->return_data;
        *out_size = result->size_return_data;
    }

    result->return_data = NULL;
    result->size_return_data = 0;

    // oe_mutex_unlock(&result->mutex);
    LeaveCriticalSection(&result->mutex);

    return return_code;
}

/* Wait until all jobs have finished */
void thpool_wait(thpool_* thpool_p)
{
    EnterCriticalSection(&thpool_p->thcount_lock);
    while (thpool_p->jobqueue.len || thpool_p->num_threads_working)
    {
        SleepConditionVariableCS(&thpool_p->threads_all_idle, &thpool_p->thcount_lock, INFINITE);
    }
    LeaveCriticalSection(&thpool_p->thcount_lock);
}

/* Destroy the threadpool */
void thpool_destroy(thpool_* thpool_p)
{
    /* No need to destroy if it's NULL */
    if (thpool_p == NULL)
        return;

    volatile int threads_total = thpool_p->num_threads_alive;

    /* End each thread 's infinite loop */
    threads_keepalive = 0;

    /* Give one second to kill idle threads */
    double TIMEOUT = 1.0;
    time_t start, end;
    double tpassed = 0.0;
    time(&start);
    while (tpassed < TIMEOUT && thpool_p->num_threads_alive)
    {
        bsem_post_all(thpool_p->jobqueue.has_jobs);
        time(&end);
        tpassed = difftime(end, start);
    }

    /* Poll remaining threads */
    while (thpool_p->num_threads_alive)
    {
        bsem_post_all(thpool_p->jobqueue.has_jobs);
        // Sleep 1 sec
#if defined(__linux__)
        sleep(1);
#elif defined(_WIN32)
        Sleep(1000);
#endif
    }

    /* Job queue cleanup */
    jobqueue_destroy(&thpool_p->jobqueue);
    /* Deallocs */
    int n;
    for (n = 0; n < threads_total; n++)
    {
        thread_destroy(thpool_p->threads[n]);
    }
    free(thpool_p->threads);
    free(thpool_p);
}

int thpool_num_threads_working(thpool_* thpool_p)
{
    return thpool_p->num_threads_working;
}

/* ============================ THREAD ============================== */

/* Initialize a thread in the thread pool
 *
 * @param thread        address to the pointer of the thread to be created
 * @param id            id to be given to the thread
 * @return 0 on success, -1 otherwise.
 */
static int thread_init(thpool_* thpool_p, struct thread** thread_p, int id)
{
    *thread_p = (struct thread*)malloc(sizeof(struct thread));
    if (*thread_p == NULL)
    {
        err("thread_init(): Could not allocate memory for thread\n");
        return -1;
    }

    (*thread_p)->thpool_p = thpool_p;
    (*thread_p)->id = id;

    oe_thread_create(
        &(*thread_p)->pthread, (void* (*)(void*))thread_do, (*thread_p));
    // pthread_detach((*thread_p)->pthread);
    return 0;
}

/* What each thread is doing
 *
 * In principle this is an endless loop. The only time this loop gets
 * interuppted is once thpool_destroy() is invoked or the program exits.
 *
 * @param  thread        thread that will run this function
 * @return nothing
 */
static void* thread_do(struct thread* thread_p)
{
    /* Set thread name for profiling and debugging */
    char thread_name[16] = {0};
    snprintf(thread_name, 16, "thpool-%d", thread_p->id);

#if defined(__linux__)
    /* Use prctl instead to prevent using _GNU_SOURCE flag and implicit
     * declaration */
    prctl(PR_SET_NAME, thread_name);
#elif defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(thread_name);
#else
    err("thread_do(): pthread_setname_np is not supported on this system");
#endif

    /* Assure all threads have been created before starting serving */
    thpool_* thpool_p = thread_p->thpool_p;

    /* Mark thread as alive (initialized) */
    EnterCriticalSection(&thpool_p->thcount_lock);
    thpool_p->num_threads_alive += 1;
    LeaveCriticalSection(&thpool_p->thcount_lock);

    while (threads_keepalive)
    {
        bsem_wait(thpool_p->jobqueue.has_jobs);

        if (threads_keepalive)
        {
            EnterCriticalSection(&thpool_p->thcount_lock);
            thpool_p->num_threads_working++;
            LeaveCriticalSection(&thpool_p->thcount_lock);

            /* Read job from queue and execute it */
            void (*func_buff)(void*, job_result*);
            void* arg_buff;
            job* job_p = jobqueue_pull(&thpool_p->jobqueue);
            if (job_p)
            {
                func_buff = job_p->function;
                arg_buff = job_p->arg;
                func_buff(arg_buff, job_p->job_result);
                free(job_p);
            }

            EnterCriticalSection(&thpool_p->thcount_lock);
            thpool_p->num_threads_working--;
            if (!thpool_p->num_threads_working)
            {
                WakeConditionVariable(&thpool_p->threads_all_idle);
            }
            LeaveCriticalSection(&thpool_p->thcount_lock);
        }
    }
    EnterCriticalSection(&thpool_p->thcount_lock);
    thpool_p->num_threads_alive--;
    LeaveCriticalSection(&thpool_p->thcount_lock);

    return NULL;
}

/* Frees a thread  */
static void thread_destroy(thread* thread_p)
{
    free(thread_p);
}

/* ============================ JOB QUEUE =========================== */

/* Initialize queue */
static int jobqueue_init(jobqueue* jobqueue_p)
{
    jobqueue_p->len = 0;
    jobqueue_p->front = NULL;
    jobqueue_p->rear = NULL;

    jobqueue_p->has_jobs = (struct bsem*)malloc(sizeof(struct bsem));
    if (jobqueue_p->has_jobs == NULL)
    {
        return -1;
    }

    oe_mutex_init(&(jobqueue_p->rwmutex));
    bsem_init(jobqueue_p->has_jobs, 0);

    return 0;
}

/* Clear the queue */
static void jobqueue_clear(jobqueue* jobqueue_p)
{
    while (jobqueue_p->len)
    {
        free(jobqueue_pull(jobqueue_p));
    }

    jobqueue_p->front = NULL;
    jobqueue_p->rear = NULL;
    bsem_reset(jobqueue_p->has_jobs);
    jobqueue_p->len = 0;
}

/* Add (allocated) job to queue
 */
static void jobqueue_push(jobqueue* jobqueue_p, struct job* newjob)
{
    oe_mutex_lock(&jobqueue_p->rwmutex);
    newjob->prev = NULL;

    switch (jobqueue_p->len)
    {
        case 0: /* if no jobs in queue */
            jobqueue_p->front = newjob;
            jobqueue_p->rear = newjob;
            break;

        default: /* if jobs in queue */
            jobqueue_p->rear->prev = newjob;
            jobqueue_p->rear = newjob;
    }
    jobqueue_p->len++;

    bsem_post(jobqueue_p->has_jobs);
    oe_mutex_unlock(&jobqueue_p->rwmutex);
}

/* Get first job from queue(removes it from queue)
 * Notice: Caller MUST hold a mutex
 */
static struct job* jobqueue_pull(jobqueue* jobqueue_p)
{
    oe_mutex_lock(&jobqueue_p->rwmutex);
    job* job_p = jobqueue_p->front;

    switch (jobqueue_p->len)
    {
        case 0: /* if no jobs in queue */
            break;

        case 1: /* if one job in queue */
            jobqueue_p->front = NULL;
            jobqueue_p->rear = NULL;
            jobqueue_p->len = 0;
            break;

        default: /* if >1 jobs in queue */
            jobqueue_p->front = job_p->prev;
            jobqueue_p->len--;
            /* more than one job in queue -> post it */
            bsem_post(jobqueue_p->has_jobs);
    }

    oe_mutex_unlock(&jobqueue_p->rwmutex);
    return job_p;
}

/* Free all queue resources back to the system */
static void jobqueue_destroy(jobqueue* jobqueue_p)
{
    jobqueue_clear(jobqueue_p);
    free(jobqueue_p->has_jobs);
}

/* ======================== SYNCHRONISATION ========================= */

/* Init semaphore to 1 or 0 */
static void bsem_init(bsem* bsem_p, int value)
{
    if (value < 0 || value > 1)
    {
        err("bsem_init(): Binary semaphore can take only values 1 or 0");
        exit(1);
    }
    InitializeCriticalSection(&(bsem_p->mutex));
    InitializeConditionVariable(&(bsem_p->cond));
    bsem_p->v = value;
}

/* Reset semaphore to 0 */
static void bsem_reset(bsem* bsem_p)
{
    bsem_init(bsem_p, 0);
}

/* Post to at least one thread */
static void bsem_post(bsem* bsem_p)
{
    // oe_mutex_lock(&bsem_p->mutex);
    EnterCriticalSection(&bsem_p->mutex);
    bsem_p->v = 1;
    WakeConditionVariable(&bsem_p->cond);
    // oe_mutex_unlock(&bsem_p->mutex);
    LeaveCriticalSection(&bsem_p->mutex);
}

/* Post to all threads */
static void bsem_post_all(bsem* bsem_p)
{
    // oe_mutex_lock(&bsem_p->mutex);
    EnterCriticalSection(&bsem_p->mutex);
    bsem_p->v = 1;
    WakeAllConditionVariable(&bsem_p->cond);
    // oe_mutex_unlock(&bsem_p->mutex);
    LeaveCriticalSection(&bsem_p->mutex);
}

/* Wait on semaphore until semaphore has value 0 */
static void bsem_wait(bsem* bsem_p)
{
    // oe_mutex_lock(&bsem_p->mutex);
    EnterCriticalSection(&bsem_p->mutex);
    while (bsem_p->v != 1)
    {
        SleepConditionVariableCS(&bsem_p->cond, &bsem_p->mutex, INFINITE);
    }
    bsem_p->v = 0;
    // oe_mutex_unlock(&bsem_p->mutex);
    LeaveCriticalSection(&bsem_p->mutex);
}
