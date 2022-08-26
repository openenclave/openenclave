// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGX_TD_H
#define _OE_SGX_TD_H

#include <openenclave/internal/defs.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_thread_data_t
**
**     This structure defines information about an enclave thread. Each
**     instance is associated with one thread control structure (TCS). This
**     structure resides in the FS segment page (referenced by the FS segment
**     register). A thread obtains its thread data structure by calling
**     oe_get_thread_data(), which fetches the address at offset zero in
**     the FS segment register (%fs:0) which contains
**     oe_thread_data_t.self_addr.
**
**==============================================================================
*/

typedef struct _oe_thread_data oe_thread_data_t;

/* Note: unused fields have a "__" prefix */
struct _oe_thread_data
{
    /* Points to start of this structure */
    uint64_t self_addr;

    uint64_t __reserved_0;
    uint64_t __stack_base_addr;
    uint64_t __stack_limit_addr;
    uint64_t __first_ssa_gpr;

    /* Here the name and offset of stack_guard complies to the properties of
       stack_guard defined in tcbhead_t(Struct for Thread Control Block). In
       this way we can make use of the compiler's support of stack smashing
       protector.
     */
    uint64_t stack_guard; /* The offset is 0x28 for x64 */

    uint64_t __reserved_1;
    uint64_t __ssa_frame_size;
    uint64_t __last_error;
    uint64_t __reserved_2;
    uint64_t __tls_addr;
    uint64_t __tls_array;
    uint64_t __exception_flag; /* number of exceptions being handled */
    uint64_t __cxx_thread_info[6];
    uint8_t __padding[16];
};

OE_CHECK_SIZE(sizeof(oe_thread_data_t), 168);

oe_thread_data_t* oe_get_thread_data(void);

/*
**==============================================================================
**
** td_t
**
**     Extended thread data
**
**==============================================================================
*/

#define TD_MAGIC 0xc90afe906c5d19a3

#define OE_THREAD_LOCAL_SPACE (OE_PAGE_SIZE)

/**
 * thread_specific_data is the last field in oe_sgx_td_t. It takes up any
 * remaining space after the declarations of the previous fields. Its size is
 * equal to sizeof(oe_sgx_td_t) - OE_OFFSETOF(oe_sgx_td_t, thread_specific_data)
 * Due to the inability to use OE_OFFSETOF on a struct while defining its
 * members, this value is computed and hard-coded.
 */
#define OE_THREAD_SPECIFIC_DATA_SIZE (3632)

typedef struct _oe_callsite oe_callsite_t;

/* Thread specific TLS atexit call parameters */
typedef struct _oe_tls_atexit
{
    void (*destructor)(void*);
    void* object;
} oe_tls_atexit_t;

typedef enum _oe_td_state
{
    OE_TD_STATE_NULL = 0,
    OE_TD_STATE_ENTERED,
    OE_TD_STATE_RUNNING,
    OE_TD_STATE_FIRST_LEVEL_EXCEPTION_HANDLING,
    OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING,
    OE_TD_STATE_EXITED,
    OE_TD_STATE_ABORTED,
} oe_td_state_t;

/* This structure manages a pool of shared memory (memory visible to both
 * the enclave and the host). An instance of this structure is maintained
 * for each thread. This structure is used in enclave/core/arena.c.
 */
typedef struct _oe_shared_memory_arena_t
{
    uint8_t* buffer;
    uint64_t capacity;
    uint64_t used;
} oe_shared_memory_arena_t;

OE_CHECK_SIZE(sizeof(oe_shared_memory_arena_t), 24);

OE_PACK_BEGIN
typedef struct _td
{
    oe_thread_data_t base;

    /* A "magic number" for sanity checking (TD_MAGIC) */
    uint64_t magic;

    /* Depth of ECALL stack (zero indicates that it is unwound) */
    uint64_t depth;

    /* Host registers saved here on entry and restored on exit */
    uint64_t eenter_rax; /* cssa set by EENTER */
    uint64_t host_rcx;   /* EENTER return address */

    /* Return arguments from OCALL */
    uint16_t oret_func;
    uint16_t oret_result;
    uint16_t padding[2];
    uint64_t oret_arg;

    /* Padding to ensure that the following callsites fields aligns with
       expectation of Windows Debugggers */
    uint64_t callsites_padding_for_windows_debuggers[3];

    /* List of oe_callsite_t structures (most recent call is first) */
    oe_callsite_t* callsites;

    /* Simulation mode is active if non-zero */
    uint64_t simulate;

    /* Host ecall context pointers */
    struct _oe_ecall_context* host_ecall_context;
    struct _oe_ecall_context* host_previous_ecall_context;

    /* The alternative stack area setup by the runtime to handle the exceptions
     */
    uint64_t exception_handler_stack;
    uint64_t exception_handler_stack_size;

    /* A 64-bit array. Only if a bit is set, the runtime will use the
     * alternative stack to handle the exception type corresponds to the
     * position of the bit */
    uint64_t exception_handler_stack_bitmask;

    uint64_t state;
    /* Hold the previous state upon every exception entries, which is
     * used to resume the state after an illegal instruction emulation */
    uint64_t previous_state;

    uint64_t exception_nesting_level;

    /* The boolean value for opt-in/out the host signal handling */
    uint64_t host_signal_unmasked;

    /* The boolean value set by enter.S when a host signal request is
     * accepted and cleared by oe_real_exception_dispatcher() in exception.c
     * when the value is set and the nesting level is zero */
    uint64_t is_handling_host_signal;

    /* The signal number passed in by the host during an exception entry.
     * The acceptable range [1, 64] is based on Linux signal implementation */
    uint64_t host_signal;

    /* A 64-bit array. Only if a bit is set, the thread will accept the
     * (host signal number - 1) corresponds to the position of the bit */
    uint64_t host_signal_bitmask;

    /* Used by the thread-based spinlock */
    uint32_t lock;

    /* Save the rsp and rbp values in the SSA when the exception handler
     * stack is set */
    uint64_t last_ssa_rsp;
    uint64_t last_ssa_rbp;

    /* The last stack pointer (set by enclave when making an OCALL) */
    uint64_t last_sp;

    /* The exception code */
    uint32_t exception_code;
    /* The exception flags */
    uint32_t exception_flags;
    /* The rip when exception happened */
    uint64_t exception_address;

    /* The threads implementations uses this to put threads on queues */
    struct _td* next;

    /* POSIX errno (renamed to prevent clash with errno macro) */
    int32_t errnum;
    int32_t padding2;

    /* Thread-specific shared memory pool (see enclave/core/arena.c) */
    oe_shared_memory_arena_t arena;

    /* TLS atexit functions (see enclave/core/sgx/threadlocal.c) */
    oe_tls_atexit_t* tls_atexit_functions;
    uint64_t num_tls_atexit_functions;

    /* The following information is only available for SGX2 and MISCSELECT is
     * set to 1 */
    /* The faulting address associated with the PF exception. Should be zero
     * for other exception types. */
    uint64_t faulting_address;
    /* The error code for PF and GP exceptions. */
    uint32_t error_code;

    /* Reserved for thread specific data. */
    uint8_t thread_specific_data[OE_THREAD_SPECIFIC_DATA_SIZE];
} oe_sgx_td_t;
OE_PACK_END

OE_CHECK_SIZE(sizeof(oe_sgx_td_t), 4096);
OE_STATIC_ASSERT(
    OE_THREAD_SPECIFIC_DATA_SIZE ==
    sizeof(oe_sgx_td_t) - OE_OFFSETOF(oe_sgx_td_t, thread_specific_data));

/* Get the thread data object for the current thread with FS check */
oe_sgx_td_t* oe_sgx_get_td();

/* Get the thread data object for the current thread without FS check */
oe_sgx_td_t* oe_sgx_get_td_no_fs_check();

void oe_sgx_td_clear_states(oe_sgx_td_t* td);

/* Only the code equal or below the maximum value is valid (see exception.h) */
#define OE_SGX_EXCEPTION_CODE_MAXIMUM 8

bool oe_sgx_td_set_exception_handler_stack(
    oe_sgx_td_t* td,
    void* stack,
    uint64_t size);

bool oe_sgx_td_register_exception_handler_stack(oe_sgx_td_t* td, uint64_t type);

bool oe_sgx_td_unregister_exception_handler_stack(
    oe_sgx_td_t* td,
    uint64_t type);

bool oe_sgx_td_exception_handler_stack_registered(
    oe_sgx_td_t* td,
    uint64_t type);

void oe_sgx_td_mask_host_signal(oe_sgx_td_t* td);

void oe_sgx_td_unmask_host_signal(oe_sgx_td_t* td);

bool oe_sgx_td_register_host_signal(oe_sgx_td_t* td, int signal_number);

bool oe_sgx_td_unregister_host_signal(oe_sgx_td_t* td, int signal_number);

bool oe_sgx_td_host_signal_registered(oe_sgx_td_t* td, int signal_number);

bool oe_sgx_td_is_handling_host_signal(oe_sgx_td_t* td);

OE_EXTERNC_END

#endif // _OE_SGX_TD_H
