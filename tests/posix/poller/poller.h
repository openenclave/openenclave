// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _POLLER_H
#define _POLLER_H

#if defined(_MSC_VER)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <stdio.h>
#include <vector>

#define POLLER_READ 1
#define POLLER_WRITE 2
#define POLLER_EXCEPT 4

enum poller_type_t
{
    POLLER_TYPE_SELECT,
    POLLER_TYPE_POLL,
};

struct event_t
{
    socket_t sock;
    uint32_t events;

    event_t() : sock(0), events(0)
    {
    }

    event_t(socket_t sock_, uint32_t events_) : sock(sock_), events(events_)
    {
    }
};

class poller
{
  public:
    poller();

    virtual ~poller();

    virtual int add(socket_t sock, uint32_t events);

    virtual int remove(socket_t sock, uint32_t events);

    virtual int wait(std::vector<event_t>& events) = 0;

    static const char* name(poller_type_t poller_type);

    static poller* create(poller_type_t poller_type);

    static void destroy(poller* poller);

    bool find(socket_t sock, event_t& event) const;

  protected:
    std::vector<event_t> _events;
};

class select_poller : public poller
{
  public:
    select_poller();

    virtual ~select_poller();

    virtual int wait(std::vector<event_t>& events);
};

#if !defined(_MSC_VER)
class poll_poller : public poller
{
  public:
    poll_poller();

    virtual ~poll_poller();

    virtual int wait(std::vector<event_t>& events);

  private:
};
#endif /* !defined(_MSC_VER) */

#if defined(_MSC_VER)
typedef select_poller poll_poller;
#endif

#endif /* _POLLER_H */
