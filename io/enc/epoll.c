// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/print.h>
#include "epoll.h"
#include "list.h"
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/trace.h>

/* For synchronizing access to all static structures defined below. */
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

/*
**==============================================================================
**
** Define a list device notifications and methods for manipulating it.
**
**     _list_append() -- append a node to the end of the list.
**     _list_remove() -- remove the given node from the list.
**
**==============================================================================
*/

typedef struct _list_node list_node_t;

struct _list_node
{
    /* Overlays the same fields in oe_list_node_t */
    list_node_t* prev;
    list_node_t* next;

    /* Extra field */
    struct _oe_device_notifications notice;
};

typedef struct _list
{
    /* Overlays the same fields in oe_list_t */
    list_node_t* head;
    list_node_t* tail;
    size_t size;
} list_t;

OE_INLINE void _list_append(list_t* list, list_node_t* node)
{
    oe_list_append((oe_list_t*)list, (oe_list_node_t*)node);
}

OE_INLINE void _list_remove(list_t* list, list_node_t* node)
{
    oe_list_remove((oe_list_t*)list, (oe_list_node_t*)node);
}

/*
**==============================================================================
**
** Define an array of list_t elements (indexed by epoll file descriptor) and
** the following functions for manipulating the array.
**
**     _array_data() -- obtain a pointer to the array.
**     _array_size() -- get the size of the array.
**     _array_resize() -- change the size of the array.
**
**==============================================================================
*/

static oe_array_t _array = OE_ARRAY_INITIALIZER(sizeof(list_t), 64);

static list_t* _array_data(void)
{
    return (list_t*)_array.data;
}

static size_t _array_size(void)
{
    return _array.size;
}

static int _array_resize(size_t new_size)
{
    return oe_array_resize(&_array, new_size);
}

/*
**==============================================================================
**
** Define functions for allocating and freeing list_node_t structures. Utilize
** a free list to improve performance.
**
**     _alloc_node() -- allocate a list node.
**     _free_node() -- free a list node.
**
**==============================================================================
*/

#define MAX_FREE_LIST_SIZE 64

static list_node_t* _free_list;
static size_t _free_list_size;

static list_node_t* _alloc_node(void)
{
    list_node_t* ret = NULL;
    list_node_t* p = NULL;

    if (_free_list)
    {
        p = _free_list;
        _free_list = p->next;
        _free_list_size--;
    }
    else
    {
        if (!(p = oe_calloc(1, sizeof(list_node_t))))
        {
            OE_TRACE_ERROR("oe_calloc with size = %zu", sizeof(list_node_t));
            goto done;
        }
    }

    memset(p, 0, sizeof(list_node_t));

    ret = p;

done:
    return ret;
}

static void _free_node(list_node_t* p)
{
    if (p && _free_list_size < MAX_FREE_LIST_SIZE)
    {
        p->next = _free_list;
        _free_list = p;
        _free_list_size++;
    }
    else
    {
        oe_free(p);
    }
}

static void _free_free_list(void)
{
    list_node_t* p;

    for (p = _free_list; p;)
    {
        list_node_t* next = p->next;
        oe_free(p);
        p = next;
    }
}

/*
**==============================================================================
**
** Define at-exit handler to free local heap memory.
**
**==============================================================================
*/

static void _atexit_function(void)
{
    for (size_t i = 0; i < _array_size(); i++)
    {
        list_t* list = _array_data() + i;
        oe_list_free((oe_list_t*)list, (oe_list_free_func)_free_node);
    }

    _free_free_list();

    oe_array_free(&_array);
}

static oe_once_t _once = OE_ONCE_INITIALIZER;

static void _once_function(void)
{
    oe_atexit(_atexit_function);
}

/*
**==============================================================================
**
** Define the epoll functions.
**
**==============================================================================
*/

static oe_cond_t poll_notification = OE_COND_INITIALIZER;
static oe_mutex_t poll_lock = OE_MUTEX_INITIALIZER;

int oe_epoll_create(int size)
{
    int ret = -1;
    int epfd = -1;
    oe_device_t* device = NULL;
    oe_device_t* epoll = NULL;

    oe_once(&_once, _once_function);

    if (!(device = oe_get_devid_device(OE_DEVID_EPOLL)))
    {
        OE_TRACE_ERROR("devid = %lu ", OE_DEVID_EPOLL);
        goto done;
    }

    if (!(epoll = (*device->ops.epoll->create)(device, size)))
    {
        OE_TRACE_ERROR("size = %d ", size);
        goto done;
    }

    if ((epfd = oe_assign_fd_device(epoll)) == -1)
    {
        OE_TRACE_ERROR("oe_assign_fd_device failed");
        goto done;
    }
    ret = 0;
    epoll = NULL;

done:

    if (epoll)
        (*device->ops.base->close)(epoll);

    return ret;
}

int oe_epoll_create1(int flags)
{
    int epfd = -1;
    oe_device_t* device = NULL;
    oe_device_t* epoll = NULL;

    oe_once(&_once, _once_function);

    if (!(device = oe_get_devid_device(OE_DEVID_EPOLL)))
    {
        OE_TRACE_ERROR("devid = %lu ", OE_DEVID_EPOLL);
        goto done;
    }

    if (!(epoll = (*device->ops.epoll->create1)(device, flags)))
    {
        OE_TRACE_ERROR("flags=%d", flags);
        goto done;
    }

    if ((epfd = oe_assign_fd_device(epoll)) == -1)
    {
        OE_TRACE_ERROR("oe_assign_fd_device failed");
        goto done;
    }

    epoll = NULL;

done:

    if (epoll)
        (*device->ops.base->close)(epoll);

    return epfd;
}

int oe_epoll_ctl(int epfd, int op, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* epoll;
    oe_device_t* device;

    oe_once(&_once, _once_function);

    oe_errno = 0;

    if (!(epoll = oe_get_fd_device(epfd, OE_DEVICE_TYPE_EPOLL)))
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!(device = oe_get_fd_device(fd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = EBADF;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
        {
            if (!epoll->ops.epoll->ctl_add)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
                goto done;
            }

            ret = (*epoll->ops.epoll->ctl_add)(epfd, fd, event);
            break;
        }
        case OE_EPOLL_CTL_DEL:
        {
            if (!epoll->ops.epoll->ctl_del)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
                goto done;
            }

            ret = (*epoll->ops.epoll->ctl_del)(epfd, fd);
            break;
        }
        case OE_EPOLL_CTL_MOD:
        {
            if (!epoll->ops.epoll->ctl_mod)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
                goto done;
            }

            ret = (*epoll->ops.epoll->ctl_mod)(epfd, fd, event);
            break;
        }
        default:
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("op=%d  fd=%d oe_errno=%d", op, fd, oe_errno);
            goto done;
        }
    }

done:
    return ret;
}

int oe_epoll_wait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    int ret = -1;
    oe_device_t* epoll;
    int n;

    oe_once(&_once, _once_function);

    if (!(epoll = oe_get_fd_device(epfd, OE_DEVICE_TYPE_EPOLL)))
    {
        OE_TRACE_ERROR("no device found epfd=%d", epfd);
        goto done;
    }

    if (!epoll->ops.epoll->wait)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    /* Wait until there are events. */
    if ((*epoll->ops.epoll->wait)(epfd, events, (size_t)maxevents, timeout) < 0)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("epfd=%d", epfd);
        goto done;
    }

    /* See if there are events waiting. */
    n = oe_get_epoll_events(epfd, (size_t)maxevents, events);

    /* If no events polled, then wait again. */
    if (n == 0)
    {
        if (oe_wait_device_notification(timeout) < 0)
        {
            oe_errno = EPROTO;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            return -1;
        }

        /* See how many events are waiting. */
        n = oe_get_epoll_events(epfd, (size_t)maxevents, events);
    }

    ret = n;

done:

    /* Return the number of descriptors that were signalled. */
    return ret;
}

int oe_epoll_pwait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout,
    const oe_sigset_t* sigmask)
{
    int ret = -1;

    if (sigmask)
    {
        oe_errno = ENOTSUP;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    ret = oe_epoll_wait(epfd, events, maxevents, timeout);

done:
    return ret;
}

int oe_post_device_notifications(
    int num_notifications,
    struct _oe_device_notifications* notices)
{
    int ret = -1;
    list_t* list;
    int locked = false;
    int i;
    size_t index;

    oe_once(&_once, _once_function);

    if (!notices)
    {
        OE_TRACE_ERROR("notices is null");
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    /* Save the epoll file descriptor (the array index). */
    index = (size_t)(notices[0].epoll_fd);

    /* Expand array if not already big enough. */
    if (_array_resize(index + 1) != 0)
    {
        OE_TRACE_ERROR("index=%zu", index);
        goto done;
    }

    /* Get the list for this epoll file descriptor. */
    if (!(list = _array_data() + index))
    {
        OE_TRACE_ERROR("list is null");
        goto done;
    }

    /* Add a new node for each notifiction. */
    for (i = 0; i < num_notifications; i++)
    {
        list_node_t* node;

        /* Allocate a new node. */
        if (!(node = _alloc_node()))
        {
            OE_TRACE_ERROR("_alloc_node failed");
            goto done;
        }

        /* Set the notifications field. */
        node->notice = notices[i];

        /* Append the new node to the end of the list. */
        _list_append(list, node);
    }

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

//
// parms: epfd is the enclave fd of the epoll
//        maxevents is the number of events in the buffer
//        pevents is storage for <maxevents> events
//
// returns: 0 = no list.
//          >0 = returned length of the list
//          <0 = something bad happened.
//
int oe_get_epoll_events(
    int epfd,
    size_t maxevents,
    struct oe_epoll_event* events)
{
    int ret = -1;
    oe_device_t* epoll;
    list_t* list;
    size_t numevents;
    int locked = false;
    size_t i;
    list_node_t* p;

    oe_once(&_once, _once_function);

    /* Check the function parameters. */
    if (!events || maxevents < 1)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!(epoll = oe_get_fd_device(epfd, OE_DEVICE_TYPE_EPOLL)))
    {
        ret = -1;
        OE_TRACE_ERROR("no device found epfd=%d", epfd);
        goto done;
    }

    /* Expand array if not already big enough. */
    if (_array_resize((size_t)epfd + 1) != 0)
    {
        OE_TRACE_ERROR("epfd=%d", epfd);
        goto done;
    }

    /* Get the list for this epid file descriptor. */
    list = _array_data() + epfd;

    /* If the list is empty. */
    if (list->size == 0)
    {
        /* Not having notifications isn't an error. */
        OE_TRACE_WARNING("no notifications");
        ret = 0;
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    /* Determine the number of events to be handled. */
    numevents = (list->size > maxevents) ? maxevents : list->size;

    /* Handle each event. */
    for (p = list->head, i = 0; p && i < numevents; i++)
    {
        events[i].events = p->notice.event_mask;

        if ((events[i].data.u64 = (*epoll->ops.epoll->get_event_data)(
                 epoll, p->notice.list_idx)) == (uint64_t)-1)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("oe_errno = %d", oe_errno);
            goto done;
        }

        /* Remove and release the current node. */
        {
            list_node_t* next = p->next;
            _list_remove(list, p);
            _free_node(p);
            p = next;
        }
    }

    ret = (int)numevents;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

//
// We accept a list of notifications so we don't get large number
// of handle notification calls in rapid succession. This could raise needless
// synchronization issues. Instead, we send the list and notify the list, the
// push the doorbell
int oe_posix_polling_notify_ecall(
    oe_device_notifications_t* notifications,
    size_t num_notifications)
{
    int ret = -1;

    oe_once(&_once, _once_function);

    if (oe_post_device_notifications((int)num_notifications, notifications) < 0)
    {
        OE_TRACE_ERROR("oe_post_device_notifications failed");
        goto done;
    }

    /* push the doorbell */
    oe_broadcast_device_notification();

    ret = 0;

done:
    return ret;
}

void oe_signal_device_notification(oe_device_t* device, uint32_t event_mask)
{
    oe_once(&_once, _once_function);
    (void)device;
    (void)event_mask;
}

void oe_broadcast_device_notification()
{
    oe_once(&_once, _once_function);
    oe_cond_broadcast(&poll_notification);
}

int oe_wait_device_notification(int timeout)
{
    (void)timeout;
    oe_once(&_once, _once_function);

    oe_mutex_lock(&poll_lock);
    oe_cond_wait(&poll_notification, &poll_lock);
    oe_mutex_unlock(&poll_lock);

    return 0;
}

void oe_clear_device_notification()
{
    oe_once(&_once, _once_function);
}
