// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#define __OE_SI_PAD_SIZE ((128 / sizeof(int)) - 4)

typedef struct
{
    int oe_si_signo;
    int oe_si_errno;
    int oe_si_code;
    union {
        int __oe_si_pad[__OE_SI_PAD_SIZE];

        /* kill() */
        struct
        {
            pid_t oe_si_pid; /* sender's pid */
            uid_t oe_si_uid; /* sender's uid */
        } __oe_si_kill;

        /* POSIX.1b timers */
        struct
        {
            void* oe_si_tid;   /* timer id */
            int oe_si_overrun; /* overrun count */
#if !defined(_MSC_VER)
            char __oe_si_pad[sizeof(uid_t) - sizeof(int)]; // This turns out to be zero length
#endif
            union oe_sigval oe_si_sigval; /* same as below */
            int oe_si_sys_private;        /* not to be passed to user */
        } __oe_si_timer;

        /* POSIX.1b signals */
        struct
        {
            pid_t oe_si_pid;    /* sender's pid */
            uint32_t oe_si_uid; /* sender's uid */
            union oe_sigval oe_si_sigval;
        } __oe_si_rt;

    } __oe_si_fields;
} __OE_SIGINFO;
