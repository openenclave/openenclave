// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ENCLAVE_CONTEXT_H
#define _ENCLAVE_CONTEXT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/user.h>

int sgx_read_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* read_size);

int sgx_write_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* write_size);

bool sgx_is_aep(pid_t pid, struct user_regs_struct* regs);

int sgx_get_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs);

int sgx_set_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs);

int sgx_get_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs);

int sgx_set_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs);

int sgx_get_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size);

int sgx_set_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size);

#endif /* _ENCLAVE_CONTEXT_H */
