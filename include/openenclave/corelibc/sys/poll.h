// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_POLL_H
#define _OE_SYS_POLL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

/* Event types that can be polled for.  These bits may be set in `events'
   to indicate the interesting event types; they will appear in `revents'
   to indicate the status of the file descriptor.  */
#define POLLIN 0x001  /* There is data to read.  */
#define POLLPRI 0x002 /* There is urgent data to read.  */
#define POLLOUT 0x004 /* Writing now will not block.  */

/* These values are defined in XPG4.2.  */
#define POLLRDNORM 0x040 /* Normal data may be read.  */
#define POLLRDBAND 0x080 /* Priority data may be read.  */
#define POLLWRNORM 0x100 /* Writing now will not block.  */
#define POLLWRBAND 0x200 /* Priority data may be written.  */

/* These are extensions for Linux.  */
#define POLLMSG 0x400
#define POLLREMOVE 0x1000
#define POLLRDHUP 0x2000

/* Event types always implicitly polled for.  These bits need not be set in
   `events', but they will appear in `revents' to indicate the status of
   the file descriptor.  */
#define POLLERR 0x008  /* Error condition.  */
#define POLLHUP 0x010  /* Hung up.  */
#define POLLNVAL 0x020 /* Invalid polling request.  */

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

/* Data structure describing a polling request.  */
struct oe_pollfd
{
    int fd;            /* File descriptor to poll.  */
    short int events;  /* Types of events poller cares about.  */
    short int revents; /* Types of events that actually occurred.  */
};

OE_EXTERNC_BEGIN

int oe_poll(struct oe_pollfd* __fds, nfds_t __nfds, int __timeout);

OE_EXTERNC_END

#endif /* _OE_SYS_POLL_H */
