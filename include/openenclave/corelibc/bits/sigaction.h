// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_STRUCT_SIGACTION
{
    /* Signal handler.  */
    union {
        oe_sighandler_t oe_sa_handler;
        void (*oe_sa_sigaction)(int, oe_siginfo_t*, void*);
    } __oe_sigaction_handler;

    /* Additional set of signals to be blocked.  */
    oe_sigset_t oe_sa_mask;

    /* Special flags.  */
    int oe_sa_flags;

    /* Restore handler.  */
    void (*oe_sa_restorer)(void); // Never used
};
