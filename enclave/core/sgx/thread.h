// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CORE_THREAD_H_H
#define _OE_CORE_THREAD_H_H

// This function is called when the enclave is finished with a thread (when
// exiting). It invokes all thread-specific-data destructors for the current
// thread.
void oe_thread_destruct_specific(void);

#endif /* _OE_CORE_THREAD_H_H */
