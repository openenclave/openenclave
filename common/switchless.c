// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/switchless.h>

#if _MSC_VER
#include <Windows.h>
#endif

void init_switchless_control(
    switchless_control* psc,
    uint32_t state,
    size_t count_limit)
{
    sc_set_state(psc, state);
    psc->count_limit = count_limit;
    init_lockless_queue(&(psc->enc_queue));
    init_lockless_queue(&(psc->host_queue));
}

uint32_t sc_get_state(switchless_control* psc)
{
#ifdef _MSC_VER
    return InterlockedCompareExchange(&(psc->_state), 0, 0);
#elif defined __GNUC__
    return __atomic_load_n(&(psc->_state), __ATOMIC_ACQUIRE);
#endif
}

void sc_set_state(switchless_control* psc, uint32_t state)
{
#ifdef _MSC_VER
    InterlockedExchange(&(psc->_state), state);
#elif defined __GNUC__
    __atomic_store_n(&(psc->_state), state, __ATOMIC_RELEASE);
#endif
}

/* This push operation uses an atomic compare_exchange_strong to allow for
     concurrent threads to push to the queue safely.
 */
void sc_push_enc_queue(switchless_control* psc, sc_queue_node* pnode)
{
    lockless_queue_push(&(psc->enc_queue), &(pnode->_node));
}

/* This pop operation allows for a single thread to pop from the queue while
     concurrent threads push to the queue.
   It is not safe for concurrent threads to pop from the queue.
 */
sc_queue_node* sc_pop_enc_queue(switchless_control* psc)
{
    return (sc_queue_node*)lockless_queue_pop(&(psc->enc_queue));
}

/* This push operation uses an atomic compare_exchange_strong to allow for
     concurrent threads to push to the queue safely.
 */
void sc_push_host_queue(switchless_control* psc, sc_queue_node* pnode)
{
    lockless_queue_push(&(psc->host_queue), &(pnode->_node));
}

/* This pop operation allows for a single thread to pop from the queue while
     concurrent threads push to the queue.
   It is not safe for concurrent threads to pop from the queue.
 */
sc_queue_node* sc_pop_host_queue(switchless_control* psc)
{
    return (sc_queue_node*)lockless_queue_pop(&(psc->host_queue));
}
