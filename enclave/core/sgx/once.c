// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>

#define FUNC_NOT_INVOKED 0
#define FUNC_BEING_INVOKED 1
#define FUNC_INVOKED 2

oe_result_t oe_once(oe_once_t* once, void (*func)(void))
{
    if (!once)
        return OE_INVALID_PARAMETER;

    oe_once_t status = *once;
    /* Double checked locking (DCLP). */
    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();

    /*
      Use an atomic-acquire load operation to check if the function has not been
      invoked. If the function has already been invoked, there is nothing to do.
      If the function is being invoked, then this thread must wait for the
      function invocation to complete. Otherwise, this thread can try to take
      ownership of invoking the function
    */
    if (status != FUNC_INVOKED)
    {
        /*
          Multiple threads could reach here simultaneously after checking
          whether the function has been invoked or not. Only one of them must
          now invoke the function and others must wait for the function
          invocation to complete.
          To determine who gets to invoke the function, each thread atomically
          compares the value of once to FUNC_NOT_INVOKED and if equal, sets the
          value to FUNC_BEING_INVOKED to signal to other threads that the
          function is being invoked. The return value of
          __sync_val_compare_and_swap determines which thread takes ownership.
          If __sync_val_compare_and_swap returns FUNC_NOT_INVOKED, then that
          means this thread successfully set once to FUNC_BEING_INVOKED, and can
          now safely call func. If __sync_val_compare_and_swap returns
          FUNC_BEING_INVOKED, this means another thread's
          __sync_val_compare_and_swap succeeded first and therefore this thread
          now has to wait for the other thread to complete (ie wait for once to
          become FUNC_INVOKED. If __sync_val_compare_and_swap returns
          FUNC_INVOKED, that means another thread has already called the
          function and marked the once as complete. This thread can safely
          proceed.
        */
        oe_once_t retval = __sync_val_compare_and_swap(
            once, FUNC_NOT_INVOKED, FUNC_BEING_INVOKED);
        if (retval == FUNC_NOT_INVOKED)
        {
            if (func)
                func();

            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            *once = FUNC_INVOKED;
        }
        else if (retval == FUNC_BEING_INVOKED)
        {
            /*
              Another thread is invoking the function. Wait for that thread to
              finish the invocation and mark the once variable to FUNC_INVOKED.
            */
            while (__sync_val_compare_and_swap(
                       once, FUNC_BEING_INVOKED, FUNC_BEING_INVOKED) !=
                   FUNC_BEING_INVOKED)
            {
                // Relinquish CPU
                asm volatile("pause");
            }
        }
    }
    return OE_OK;
}
