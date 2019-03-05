// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/epoll.h>

int oe_get_epoll_events(
    uint64_t epfd,
    size_t maxevents,
    struct oe_epoll_event* pevents);

int oe_epoll_create(int size)
{
    int ed = -1;
    oe_device_t* pepoll = NULL;
    oe_device_t* pdevice = NULL;

    pdevice = oe_get_devid_device(OE_DEVID_EPOLL);
    if ((pepoll = (*pdevice->ops.epoll->create)(pdevice, size)) == NULL)
    {
        return -1;
    }
    ed = oe_assign_fd_device(pepoll);
    if (ed == -1)
    {
        // ATTN: release pepoll here.
        // Log error here
        return -1; // erno is already set
    }

    return ed;
}

int oe_epoll_create1(int flags)
{
    int ed = -1;
    oe_device_t* pepoll = NULL;
    oe_device_t* pdevice = NULL;

    pdevice = oe_get_devid_device(OE_DEVID_EPOLL);
    if ((pepoll = (*pdevice->ops.epoll->create1)(pdevice, flags)) == NULL)
    {
        return -1;
    }
    ed = oe_assign_fd_device(pepoll);
    if (ed == -1)
    {
        // ATTN: release pepoll here.
        // Log error here
        return -1; // erno is already set
    }

    return ed;
}

int oe_epoll_ctl(int epfd, int op, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* pepoll = oe_get_fd_device(epfd);
    oe_device_t* pdevice = oe_get_fd_device(fd);

    oe_errno = 0;
    /* Check parameters. */
    if (!pepoll || !pdevice)
    {
        oe_errno = EBADF;
        return -1;
    }

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
        {
            if (pepoll->ops.epoll->ctl_add == NULL)
            {
                oe_errno = EINVAL;
                return -1;
            }
            ret = (*pepoll->ops.epoll->ctl_add)(epfd, fd, event);
            break;
        }
        case OE_EPOLL_CTL_DEL:
        {
            ret = (*pepoll->ops.epoll->ctl_del)(epfd, fd);
            break;
        }
        case OE_EPOLL_CTL_MOD:
        {
            ret = (*pepoll->ops.epoll->ctl_del)(epfd, fd);
            break;
        }
        default:
        {
            oe_errno = EINVAL;
            return -1;
        }
    }

    return ret;
}

int oe_epoll_wait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    oe_device_t* pepoll = oe_get_fd_device(epfd);
    int ret = -1;
    bool has_host_wait =
        true; // false; // 2do. We need to figure out how to wait

    if (!pepoll)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (pepoll->ops.epoll->wait == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // Start an outboard waiter if host involved
    // search polled device list for host involved  2Do
    if (has_host_wait)
    {
        if ((ret = (*pepoll->ops.epoll->wait)(
                 epfd, events, (size_t)maxevents, timeout)) < 0)
        {
            oe_errno = EINVAL;
            return -1;
        }
    }

    // We check immedately because we might have gotten lucky and had stuff come
    // in immediately. If so we skip the wait
    ret = oe_get_epoll_events((uint64_t)epfd, (size_t)maxevents, events);

    if (ret == 0)
    {
        if (oe_wait_device_notification(timeout) < 0)
        {
            oe_errno = EPROTO;
            return -1;
        }
        ret = oe_get_epoll_events((uint64_t)epfd, (size_t)maxevents, events);
    }

    return ret; // return the number of descriptors that have signalled
}

#if MAYBE
int oe_epoll_pwait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout,
    const sigset_t* ss)
{
    return -1;
}

#endif

static oe_cond_t poll_notification = OE_COND_INITIALIZER;
static oe_mutex_t poll_lock = OE_MUTEX_INITIALIZER;

static const size_t NODE_CHUNK = 256;

struct _notification_node
{
    struct oe_device_notifications notice;
    struct _notification_node* pnext;
};

struct _notification_node_chunk
{
    size_t maxnodes;
    size_t numnodes;
    struct _notification_node nodes[NODE_CHUNK];
    struct _notification_node_chunk* pnext;
};

static const size_t ELEMENT_SIZE = sizeof(struct _notification_node*);
static const size_t CHUNK_SIZE = 8;
static oe_array_t _arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

OE_INLINE struct _notification_node** _table(void)
{
    return (struct _notification_node**)_arr.data;
}

#if 0
OE_INLINE size_t _table_size(void)
{
    return _arr.size;
}

static void _free_table(void)
{
    oe_array_free(&_arr);
}

#endif

// This gets locked in outer levels

static struct _notification_node** _notification_list(uint64_t epoll_id)
{
    struct _notification_node** ret = NULL;

    if (epoll_id >= _arr.size)
    {
        if (oe_array_resize(&_arr, epoll_id + 1) != 0)
        {
            oe_errno = ENOMEM;
            goto done;
        }
    }

    ret = _table() + epoll_id;

done:

    return ret;
}

//
// We allocate an array of notification_nodes whose roots are accessed by the
// array _arr indexed by the epoll fd We allocate the nodes from chunks. Since
// the nodes are linked lists, we need to preserve addresses, so cannot use
// oe_realloc on the actual list nodes. So we allocate chunks, invalidate the

static struct _notification_node_chunk* pdevice_notice_chunks = NULL;
static struct _notification_node_chunk* pdevice_notice_chunk_tail = NULL;

static struct _notification_node* _new_notification()
{
    struct _notification_node_chunk* pchunk;

    if (!pdevice_notice_chunk_tail)
    {
        // We never had a notice posted. Everything is null.
        pdevice_notice_chunks = (struct _notification_node_chunk*)oe_calloc(
            1, sizeof(struct _notification_node_chunk));
        pdevice_notice_chunk_tail = pdevice_notice_chunks;
        pdevice_notice_chunk_tail->maxnodes = NODE_CHUNK;
        pdevice_notice_chunk_tail->numnodes = 1; // Because we are returning one
        pdevice_notice_chunk_tail->pnext = NULL;
        return &pdevice_notice_chunk_tail->nodes[0];
    }

    // We look for a node chunk with some room
    for (pchunk = pdevice_notice_chunks; pchunk != NULL; pchunk = pchunk->pnext)
    {
        if (pchunk->numnodes < pchunk->maxnodes)
        {
            break;
        }
    }

    // If we went through the entire list and the chunks are all full, we need a
    // new chunk. We expect this to happen very seldom we don't free chunks
    // until atend
    if (pchunk == NULL)
    {
        pdevice_notice_chunk_tail->pnext =
            (struct _notification_node_chunk*)oe_calloc(
                1, sizeof(struct _notification_node_chunk));
        pdevice_notice_chunk_tail = pdevice_notice_chunk_tail->pnext;
        pdevice_notice_chunk_tail->maxnodes = NODE_CHUNK;
        pdevice_notice_chunk_tail->numnodes = 1; // Because we are returning one
        pdevice_notice_chunk_tail->pnext = NULL;
        return &pdevice_notice_chunk_tail->nodes[0];
    }

    // Find a node . First on the top as the cheapest guess
    size_t nodeidx = pchunk->numnodes;
    while (nodeidx < pchunk->maxnodes)
    {
        if (pchunk->nodes[nodeidx].notice.event_mask == 0)
        {
            // We found one. Now its taken
            pchunk->numnodes++;
            return &pchunk->nodes[nodeidx];
        }
        nodeidx++;
    }

    // Find a node . Next lower half. This should find it or something is broken
    nodeidx = 0;
    while (nodeidx < pchunk->numnodes)
    {
        if (pchunk->nodes[nodeidx].notice.event_mask == 0)
        {
            // We found one
            pchunk->numnodes++;
            return &pchunk->nodes[nodeidx];
        }
        nodeidx++;
    }
    return NULL; // Should be an assert. We can't get here unless there is a bug
}

int oe_post_device_notifications(
    int num_notifications,
    struct oe_device_notifications* notices)
{
    struct _notification_node** pplist = NULL;
    struct _notification_node* pnode = NULL;
    struct _notification_node* ptail = NULL;
    int locked = false;

    if (!notices)
    {
        // complain and throw something as notices are not allowed be null
        return -1;
    }

    oe_spin_lock(&_lock);
    locked = true;

    // We believe that all of the notifications in the list are going to the
    // same epoll.
    pplist = _notification_list(notices[0].epoll_fd);
    pnode = _new_notification();
    pnode->notice = notices[0];
    if (*pplist == NULL)
    {
        *pplist = pnode;
        ptail = pnode;
    }
    else
    {
        // Find the end of the list. This will almost certainly not be hit, but
        // it could be if we report more than once before epoll_wait returns.
        for (ptail = *pplist; ptail->pnext;)
        {
            if (!ptail->pnext)
            {
                break;
            }
            ptail = ptail->pnext;
        }
        ptail->pnext = pnode;
        ptail = pnode;
    }

    int i = 1;
    for (; i < num_notifications; i++)
    {
        pnode = _new_notification();

        pnode->notice = notices[i];
        ptail->pnext = pnode;
        ptail = ptail->pnext;
    }

    if (locked)
        oe_spin_unlock(&_lock);

    return 0;
}

// parms: epfd is the enclave fd of the epoll
//        maxevents is the number of events in the buffer
//        pevents is storage for <maxevents> events
//
// returns: 0 = no list.
//          >0 = returned length of the list
//          <0 = something bad happened.
//
//
int oe_get_epoll_events(
    uint64_t epfd,
    size_t maxevents,
    struct oe_epoll_event* pevents)

{
    oe_device_t* pepoll = oe_get_fd_device((int)epfd); // this limit checks fd
    struct _notification_node** pplist = NULL;
    struct _notification_node* plist = NULL;
    struct _notification_node* ptail = NULL;
    size_t numevents = 0;
    size_t i = 0;
    int locked = false;

    if (epfd >= _arr.size)
    {
        if (oe_array_resize(&_arr, epfd + 1) != 0)
        {
            oe_errno = ENOMEM;
            return -1;
        }
    }

    pplist = _table() + epfd;
    if (!*pplist)
    {
        // Not having notifications isn't an error
        return 0;
    }

    if (!pevents || maxevents < 1)
    {
        oe_errno = EINVAL;
        return -1;
    }

    oe_spin_lock(&_lock);
    locked = true;
    plist = *pplist;

    // Count the list.
    for (ptail = plist; ptail; ptail = ptail->pnext)
    {
        numevents++;
    }

    if (numevents > maxevents)
    {
        numevents = maxevents;
    }

    ptail = plist; // We take from the front and invalidate the nodes as we go.
                   // Then we put whats left onto the _arr array
    for (i = 0; ptail && i < numevents; i++)
    {
        pevents[i].events = ptail->notice.event_mask;
        if ((pevents[i].data.u64 = (*pepoll->ops.epoll->geteventdata)(
                 pepoll, ptail->notice.list_idx)) == (uint64_t)-1)
        {
            oe_errno = EINVAL;
            return -1;
        }
        ptail->notice.event_mask = 0; // Invalidate the node.
        ptail = ptail->pnext;
    }
    *pplist = ptail;
    if (locked)
        oe_spin_unlock(&_lock);

    return (int)numevents;
}

//
// We accept a list of notifications so we don't get large number
// of handle notification calls in rapid succesion. This could raise needless
// synchronisaion issues. Instead, we send the list and notify the list, the
// push the doorbell
oe_result_t _handle_oe_device_notification(uint64_t arg)
{
    oe_result_t result = OE_FAILURE;
    struct oe_device_notification_args* pargs =
        (struct oe_device_notification_args*)arg;
    uint64_t num_notifications;

    if (pargs == NULL)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }
    num_notifications = pargs->num_notifications;
    if (!oe_is_outside_enclave(
            (void*)pargs,
            sizeof(struct oe_device_notification_args) +
                (sizeof(struct oe_device_notifications) * num_notifications)))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (oe_post_device_notifications(
            (int)pargs->num_notifications,
            (struct oe_device_notifications*)(pargs + 1)) < 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* push the doorbell */
    oe_broadcast_device_notification();

    result = OE_OK;
done:
    return result;
}

void oe_signal_device_notification(oe_device_t* pdevice, uint32_t event_mask)
{
    (void)pdevice;
    (void)event_mask;
}

void oe_broadcast_device_notification()
{
    //    oe_result_t rslt =
    oe_cond_broadcast(&poll_notification);
}

int oe_wait_device_notification(int timeout)
{
    (void)timeout;

    oe_mutex_lock(&poll_lock);
    oe_cond_wait(&poll_notification, &poll_lock);
    oe_mutex_unlock(&poll_lock);

    return 0;
}

void oe_clear_device_notification()
{
}
