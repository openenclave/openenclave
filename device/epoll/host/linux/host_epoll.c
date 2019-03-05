// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/epoll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../common/epollargs.h"

extern void (*oe_handle_epoll_ocall_callback)(void*);

static void* epoll_wait_thread(void* arg_)

{
    int ret = 0;
    struct _oe_epoll_args* args = (struct _oe_epoll_args*)arg_;

    ret = epoll_wait(
        (int)args->u.wait.epoll_fd,
        (struct epoll_event*)args->buf,
        (int)args->u.wait.maxevents,
        /*(int)args->u.wait.timeout*/ -1);
    printf("timeout = %d\n", args->u.wait.timeout);
    if (ret >= 0)
    {
        struct oe_device_notification_args* notify_arg =
            (struct oe_device_notification_args*)calloc(
                1,
                sizeof(struct oe_device_notification_args) +
                    sizeof(struct oe_device_notifications) * (size_t)ret);

        notify_arg->num_notifications = (size_t)ret;
        struct oe_device_notifications* notifications =
            (struct oe_device_notifications*)(notify_arg + 1);
        struct epoll_event* ev = (struct epoll_event*)(args->buf);
        int i = 0;
        for (; i < ret; i++)
        {
            notifications[i] = ((struct oe_device_notifications*)ev)[i];

            printf(
                "notification[%d] = events: %d data: %ld\n",
                i,
                ev[i].events,
                ev[i].data.u64);
        }

        // We come back on timeout as well.
        oe_result_t result = oe_ecall(
            (struct _oe_enclave*)(args->u.wait.enclaveid),
            OE_ECALL_DEVICE_NOTIFICATION,
            (uint64_t)notify_arg,
            NULL);
        if (result != OE_OK)
        {
            goto done;
        }
    }

done:
    return NULL;
}

static void _handle_hostepoll_ocall(void* args_)
{
    oe_epoll_args_t* args = (oe_epoll_args_t*)args_;

    /* ATTN: handle errno propagation. */

    if (!args)
        return;

    args->err = 0;
    switch (args->op)
    {
        case OE_EPOLL_OP_NONE:
        {
            break;
        }
        case OE_EPOLL_OP_CREATE:
        {
            printf("host epoll create\n");
            args->u.create.ret = epoll_create1(args->u.create.flags);
            break;
        }
        case OE_EPOLL_OP_CLOSE:
        {
            args->u.close.ret = close((int)args->u.close.host_fd);
            break;
        }
        case OE_EPOLL_OP_ADD:
        {
            union _oe_ev_data ev_data = {
                .event_list_idx = (uint32_t)args->u.ctl_add.list_idx,
                .epoll_enclave_fd = (uint32_t)args->u.ctl_add.epoll_enclave_fd};

            struct epoll_event ev = {
                .events = args->u.ctl_add.event_mask,
                .data.u64 = ev_data.data,
            };

            args->u.ctl_add.ret = epoll_ctl(
                (int)args->u.ctl_add.epoll_fd,
                EPOLL_CTL_ADD,
                (int)args->u.ctl_add.host_fd,
                &ev);
            break;
        }
        case OE_EPOLL_OP_MOD:
        {
            union _oe_ev_data ev_data = {
                .event_list_idx = (uint32_t)args->u.ctl_mod.list_idx,
                .epoll_enclave_fd = (uint32_t)args->u.ctl_mod.epoll_fd,
            };

            struct epoll_event ev = {
                .events = args->u.ctl_mod.event_mask,
                .data.u64 = ev_data.data,
            };

            args->u.ctl_mod.ret = epoll_ctl(
                (int)args->u.ctl_mod.epoll_fd,
                EPOLL_CTL_MOD,
                (int)args->u.ctl_mod.host_fd,
                &ev);
            break;
        }
        case OE_EPOLL_OP_DEL:
        {
            args->u.ctl_del.ret = epoll_ctl(
                (int)args->u.ctl_del.epoll_fd,
                EPOLL_CTL_DEL,
                (int)args->u.ctl_del.host_fd,
                NULL);

            // If in windows, delete auxiliary data, such as WSASocketEvents so
            // as not to leak handles.
            break;
        }
        case OE_EPOLL_OP_WAIT:
        {
            pthread_t wait_thread_id =
                0; // we lose the wait thread when we exit the func,
                   // but the thread will die on its own
            // copy args then spawn pthread to do the waiting. That way we can
            // ecall with notification. the thread args are freed by the thread
            // func

            size_t eventsize = (args->u.wait.maxevents < 0)
                                   ? 0
                                   : sizeof(struct oe_epoll_event) *
                                         (size_t)args->u.wait.maxevents;

            struct _oe_epoll_args* thread_args =
                (struct _oe_epoll_args*)calloc(1, sizeof(args) + eventsize);
            memcpy(thread_args, args, sizeof(args) + eventsize);

            if (pthread_create(
                    &wait_thread_id, NULL, epoll_wait_thread, thread_args) < 0)
            {
                // Complain and return
                args->u.wait.ret = -1;
            }
            args->u.wait.ret = 0;
            break;
        }
        case OE_EPOLL_OP_SHUTDOWN_DEVICE:
        {
            // 2do
            break;
        }
        default:
        {
            // Invalid
            break;
        }
    }
    args->err = errno;
}

void oe_epoll_install_hostepoll(void)
{
    oe_handle_epoll_ocall_callback = _handle_hostepoll_ocall;
}
