// Copyright (c) Open Enclave SDK contributors.
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

    /* Double checked locking (DCLP). */
    /* DCLP Acquire barrier. */

    oe_once_t status = __atomic_load_n(once, __ATOMIC_ACQUIRE);

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
          function is being invoked.

          If the compare and exchange succeeds, then this thread owns the
          responsibility of invoking the function.

          If the compare and exchange fails, then another thread has taken
          ownership of calling the function and therefore this thread must
          wait for the other thread to complete the invocation.

        */
        oe_once_t expected = FUNC_NOT_INVOKED;
        bool retval = __atomic_compare_exchange_n(
            once,
            &expected, // If the current value of once if FUNC_NOT_INVOKED
            FUNC_BEING_INVOKED, // take ownership of calling the function.
            false,              // Use a strong compare exchange.
            __ATOMIC_RELEASE,   // If exchange was successful, use release
                                // barrier.
            __ATOMIC_ACQUIRE);  // Otherwise use acquire barrier.

        if (retval)
        {
            if (func)
                func();

            // Inform other threads that func has completed by setting it to
            // FUNC_INVOKED. Use a release barrier.
            __atomic_store_n(once, FUNC_INVOKED, __ATOMIC_RELEASE);
        }
        else
        {
            /*
              Another thread is invoking the function. Wait for that thread to
              finish the invocation.
            */
            while (__atomic_load_n(once, __ATOMIC_ACQUIRE) != FUNC_INVOKED)
            {
                // Relinquish CPU
                OE_CPU_RELAX();
            }
        }
    }
    return OE_OK;
}
