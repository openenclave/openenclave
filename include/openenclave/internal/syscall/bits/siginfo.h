// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#define __OE_SI_PAD_SIZE ((128 / sizeof(int)) - 4)

typedef struct
{
    int oe_si_signo;
    int oe_si_errno;
    int oe_si_code;
    union
    {
        int __oe_si_pad[__OE_SI_PAD_SIZE];

        /* kill() */
        struct
        {
            oe_pid_t oe_si_pid;
            oe_uid_t oe_si_uid;
        } __oe_si_kill;

        /* POSIX.1b timers */
        struct
        {
            void* oe_si_tid;
            int oe_si_overrun;
#if !defined(_MSC_VER)
            char __oe_si_pad[sizeof(oe_uid_t) - sizeof(int)];
#endif
            union oe_sigval oe_si_sigval;
            int oe_si_sys_private;
        } __oe_si_timer;

        /* POSIX.1b signals */
        struct
        {
            oe_pid_t oe_si_pid;
            uint32_t oe_si_uid;
            union oe_sigval oe_si_sigval;
        } __oe_si_rt;

    } __oe_si_fields;
} __OE_SIGINFO_T;
