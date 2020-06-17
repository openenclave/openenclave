// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CONTEXT_H
#define _OE_ENCLAVE_CONTEXT_H

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/sgx/td.h>
#include <pthread.h>
#include <sys/user.h>

int oe_read_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* read_size);

int oe_write_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* write_size);

bool oe_is_aep(pid_t pid, struct user_regs_struct* regs);

int oe_get_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs);

int oe_set_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs);

int oe_get_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs);

int oe_set_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs);

int oe_get_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size);

int oe_set_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size);

#endif /* _OE_ENCLAVE_CONTEXT_H */
