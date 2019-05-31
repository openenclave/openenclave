// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _POLLER_H
#define _POLLER_H

#if defined(WINDOWS_HOST)
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
#ifndef WINDOWS_HOST
    POLLER_TYPE_POLL,
#endif
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
    virtual ~poller()
    {
    }

    virtual int add(socket_t sock, uint32_t events) = 0;

    virtual int remove(socket_t sock, uint32_t events) = 0;

    virtual int wait(std::vector<event_t>& events) = 0;

    static const char* name(poller_type_t poller_type);

    static poller* create(poller_type_t poller_type);

    static void destroy(poller* poller);
};

class select_poller : public poller
{
  public:
    select_poller() : _max(0)
    {
        FD_ZERO(&_rfds);
        FD_ZERO(&_wfds);
        FD_ZERO(&_xfds);
    }

    virtual ~select_poller()
    {
    }

    virtual int add(socket_t sock, uint32_t events)
    {
        if ((events & POLLER_READ))
            FD_SET((uint32_t)sock, &_rfds);

        if ((events & POLLER_WRITE))
            FD_SET((uint32_t)sock, &_wfds);

        if ((events & POLLER_EXCEPT))
            FD_SET((uint32_t)sock, &_xfds);

        if (sock > _max)
            _max = sock;

        return 0;
    }

    virtual int remove(socket_t sock, uint32_t events)
    {
        if ((events & POLLER_READ))
            FD_CLR((uint32_t)sock, &_rfds);

        if ((events & POLLER_WRITE))
            FD_CLR((uint32_t)sock, &_wfds);

        if ((events & POLLER_EXCEPT))
            FD_CLR((uint32_t)sock, &_xfds);

        return 0;
    }

    virtual int wait(std::vector<event_t>& events)
    {
        int ret = -1;
        fd_set rfds;
        fd_set wfds;
        fd_set xfds;
        int nfds;

        events.clear();

        memcpy(&rfds, &_rfds, sizeof(rfds));
        memcpy(&wfds, &_wfds, sizeof(wfds));
        memcpy(&xfds, &_xfds, sizeof(xfds));

        if ((nfds = sock_select(_max + 1, &rfds, &wfds, &xfds, NULL)) < 0)
            goto done;

        for (socket_t sock = 0; sock < _max + 1; sock++)
        {
            if (FD_ISSET((uint32_t)sock, &rfds))
                events.push_back(event_t(sock, POLLER_READ));

            if (FD_ISSET((uint32_t)sock, &wfds))
                events.push_back(event_t(sock, POLLER_WRITE));

            if (FD_ISSET((uint32_t)sock, &xfds))
                events.push_back(event_t(sock, POLLER_EXCEPT));
        }

        ret = 0;

    done:
        return ret;
    }

  private:
    fd_set _rfds;
    fd_set _wfds;
    fd_set _xfds;
    socket_t _max;
};

#ifndef WINDOWS_HOST
class poll_poller : public poller
{
  public:
    poll_poller()
    {
    }

    virtual ~poll_poller()
    {
    }

    virtual int add(socket_t sock, uint32_t events)
    {
        std::vector<struct pollfd>::iterator p = _pollfds.begin();
        std::vector<struct pollfd>::iterator end = _pollfds.end();

        for (; p != end; p++)
        {
            struct pollfd& pollfd = *p;

            if (pollfd.fd == sock)
            {
                if ((events & POLLER_READ))
                    pollfd.events |= (POLLIN | POLLRDNORM | POLLRDBAND);

                if ((events & POLLER_WRITE))
                    pollfd.events |= (POLLOUT | POLLWRNORM | POLLWRBAND);

                if ((events & POLLER_EXCEPT))
                    pollfd.events |= (POLLERR | POLLHUP | POLLRDHUP);

                return 0;
            }
        }

        {
            struct pollfd pollfd;

            memset(&pollfd, 0, sizeof(pollfd));

            pollfd.fd = sock;

            if ((events & POLLER_READ))
                pollfd.events |= (POLLIN | POLLRDNORM | POLLRDBAND);

            if ((events & POLLER_WRITE))
                pollfd.events |= (POLLOUT | POLLWRNORM | POLLWRBAND);

            if ((events & POLLER_EXCEPT))
                pollfd.events |= (POLLERR | POLLHUP | POLLRDHUP);

            _pollfds.push_back(pollfd);
        }

        return 0;
    }

    virtual int remove(socket_t sock, uint32_t events)
    {
        std::vector<struct pollfd>::iterator p = _pollfds.begin();
        std::vector<struct pollfd>::iterator end = _pollfds.end();

        for (; p != end; p++)
        {
            struct pollfd& pollfd = *p;

            if (pollfd.fd == sock)
            {
                if ((events & POLLER_READ))
                    pollfd.events &= ~(POLLIN | POLLRDNORM | POLLRDBAND);

                if ((events & POLLER_WRITE))
                    pollfd.events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);

                if ((events & POLLER_EXCEPT))
                    pollfd.events &= ~(POLLERR | POLLHUP | POLLRDHUP);

                if (pollfd.events == 0)
                {
                    _pollfds.erase(p);
                }

                break;
            }
        }

        return 0;
    }

    virtual int wait(std::vector<event_t>& events)
    {
        if (poll(&_pollfds[0], _pollfds.size(), -1) == -1)
            return -1;

        events.clear();

        std::vector<struct pollfd>::iterator p = _pollfds.begin();
        std::vector<struct pollfd>::iterator end = _pollfds.end();

        for (; p != end; p++)
        {
            struct pollfd& pollfd = *p;

            if (pollfd.revents & (POLLIN | POLLRDNORM | POLLRDBAND))
                events.push_back(event_t(pollfd.fd, POLLER_READ));

            if (pollfd.revents & (POLLOUT | POLLWRNORM | POLLWRBAND))
                events.push_back(event_t(pollfd.fd, POLLER_WRITE));

            if (pollfd.revents & (POLLERR | POLLHUP | POLLRDHUP))
                events.push_back(event_t(pollfd.fd, POLLER_EXCEPT));
        }

        return 0;
    }

  private:
    std::vector<struct pollfd> _pollfds;
};
#endif

inline poller* poller::create(poller_type_t poller_type)
{
    switch (poller_type)
    {
        case POLLER_TYPE_SELECT:
            return new select_poller();
#ifndef WINDOWS_HOST
        case POLLER_TYPE_POLL:
            return new poll_poller();
#endif
    }

    return NULL;
}

inline const char* poller::name(poller_type_t poller_type)
{
    switch (poller_type)
    {
        case POLLER_TYPE_SELECT:
            return "select";
#ifndef WINDOWS_HOST
        case POLLER_TYPE_POLL:
            return "poll";
#endif
    }

    return "none";
}

inline void poller::destroy(poller* poller)
{
    delete poller;
}

#endif /* _POLLER_H */
