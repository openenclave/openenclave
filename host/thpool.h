// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**********************************
 * @author      Johan Hanssen Seferidis
 * License:     MIT
 *
 **********************************/

#ifndef _THPOOL_
#define _THPOOL_

#ifdef __cplusplus
extern "C"
{
#endif

    /* =================================== API
     * ======================================= */

    typedef struct thpool_* threadpool;
    /*
    Holds the return data from a job
    This is allocated by thpool
    Caller is responsible for freeing the allocated memory
     */
    typedef struct _job_result* jobresult;

    /**
     * @brief  Initialize threadpool
     *
     * Initializes a threadpool. This function will not return until all
     * threads have initialized successfully.
     *
     * @example
     *
     *    ..
     *    threadpool thpool;                     //First we declare a threadpool
     *    thpool = thpool_init(4);               //then we initialize it to 4
     * threads
     *    ..
     *
     * @param  num_threads   number of threads to be created in the threadpool
     * @return threadpool    created threadpool on success,
     *                       NULL on error
     */
    threadpool thpool_init(int num_threads);

    /**
     * @brief Add work to the job queue
     *
     * Takes an action and its argument and adds it to the threadpool's job
     * queue. If you want to add to work a function with more than one arguments
     * then a way to implement this is by passing a pointer to a structure.
     *
     * NOTICE: You have to cast both the function and argument to not get
     * warnings.
     *
     * @example
     *
     *    void print_num(int num){
     *       printf("%d\n", num);
     *    }
     *
     *    int main() {
     *       ..
     *       int a = 10;
     *       thpool_add_work(thpool, (void*)print_num, (void*)a);
     *       ..
     *    }
     *
     * @param  threadpool    threadpool to which the work will be added
     * @param  function_p    pointer to function to add as work
     * @param  arg_p         pointer to an argument
     * @return 0 on success, -1 otherwise.
     */
    int thpool_add_work(
        threadpool,
        void (*function_p)(void*, jobresult),
        void* arg_p,
        jobresult);

    /**
     * One call to this must be paired with thpool_destroy_result
     */
    jobresult thpool_init_result(void);
    void thpool_destroy_result(jobresult);

    /**
     * Task should allocate data. Caller is responsible for freeing the
     * allocated memory.
     *
     * Transfer ownership of data to jobresult
     */
    void thpool_provide_result(jobresult, int, void* data, size_t);

    /**
     * Caller is responsible for freeing the allocated memory pointed by out.
     *
     * Transfer ownership of jobresult->return_data to out (caller)
     */
    int thpool_consume_result(jobresult, void** out, size_t*);

    /**
     * @brief Wait for all queued jobs to finish
     *
     * Will wait for all jobs - both queued and currently running to finish.
     * Once the queue is empty and all work has completed, the calling thread
     * (probably the main program) will continue.
     *
     * Smart polling is used in wait. The polling is initially 0 - meaning that
     * there is virtually no polling at all. If after 1 seconds the threads
     * haven't finished, the polling interval starts growing exponentially
     * until it reaches max_secs seconds. Then it jumps down to a maximum
     * polling interval assuming that heavy processing is being used in the
     * threadpool.
     *
     * @example
     *
     *    ..
     *    threadpool thpool = thpool_init(4);
     *    ..
     *    // Add a bunch of work
     *    ..
     *    thpool_wait(thpool);
     *    puts("All added work has finished");
     *    ..
     *
     * @param threadpool     the threadpool to wait for
     * @return nothing
     */
    void thpool_wait(threadpool);

    /**
     * @brief Destroy the threadpool
     *
     * This will wait for the currently active threads to finish and then 'kill'
     * the whole threadpool to free up memory.
     *
     * @example
     * int main() {
     *    threadpool thpool1 = thpool_init(2);
     *    threadpool thpool2 = thpool_init(2);
     *    ..
     *    thpool_destroy(thpool1);
     *    ..
     *    return 0;
     * }
     *
     * @param threadpool     the threadpool to destroy
     * @return nothing
     */
    void thpool_destroy(threadpool);

    /**
     * @brief Show currently working threads
     *
     * Working threads are the threads that are performing work (not idle).
     *
     * @example
     * int main() {
     *    threadpool thpool1 = thpool_init(2);
     *    threadpool thpool2 = thpool_init(2);
     *    ..
     *    printf("Working threads: %d\n", thpool_num_threads_working(thpool1));
     *    ..
     *    return 0;
     * }
     *
     * @param threadpool     the threadpool of interest
     * @return integer       number of threads working
     */
    int thpool_num_threads_working(threadpool);

#ifdef __cplusplus
}
#endif

#endif
