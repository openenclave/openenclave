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
    POLLER_TYPE_POLL,
    POLLER_TYPE_EPOLL,
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

class base_poller : public poller
{
  public:
    base_poller()
    {
    }

    virtual ~base_poller()
    {
    }

    virtual int add(socket_t sock, uint32_t events)
    {
        std::vector<event_t>::iterator p = _events.begin();
        std::vector<event_t>::iterator end = _events.end();

        for (; p != end; p++)
        {
            event_t& event = *p;

            if (event.sock == sock)
            {
                event.events |= events;
                return 0;
            }
        }

        _events.push_back(event_t(sock, events));
        return 0;
    }

    virtual int remove(socket_t sock, uint32_t events)
    {
        std::vector<event_t>::iterator p = _events.begin();
        std::vector<event_t>::iterator end = _events.end();

        for (; p != end; p++)
        {
            event_t& event = *p;

            if (event.sock == sock)
            {
                event.events &= ~events;

                if (event.events == 0)
                    _events.erase(p);

                return 0;
            }
        }

        return -1;
    }

    virtual int wait(std::vector<event_t>& events)
    {
        OE_UNUSED(events);
        return -1;
    }

    bool find(socket_t sock, event_t& event) const
    {
        for (size_t i = 0; i < _events.size(); i++)
        {
            if (_events[i].sock == sock)
            {
                event = _events[i];
                return true;
            }
        }

        return false;
    }

  protected:
    std::vector<event_t> _events;
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

#ifdef WINDOWS_HOST
typedef select_poller poll_poller;
#else
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

#ifdef WINDOWS_HOST
typedef select_poller epoll_poller;
#else
class epoll_poller : public base_poller
{
  public:
    epoll_poller()
    {
        _epfd = epoll_create1(0);
    }

    virtual ~epoll_poller()
    {
        close(_epfd);
    }

    virtual int add(socket_t sock, uint32_t events)
    {
        event_t event;

        if (find(sock, event))
        {
            struct epoll_event epoll_event;
            event_t event;

            memset(&epoll_event, 0, sizeof(struct epoll_event));
            epoll_event.data.fd = sock;
            epoll_event.events = 0;

            events |= event.events;

            if ((events & POLLER_READ))
                epoll_event.events |= EPOLLIN;

            if ((events & POLLER_WRITE))
                epoll_event.events |= EPOLLOUT;

            if ((events & POLLER_EXCEPT))
                epoll_event.events |= EPOLLERR;

            if (epoll_ctl(_epfd, EPOLL_CTL_MOD, sock, &epoll_event) != 0)
                return -1;
        }
        else
        {
            struct epoll_event epoll_event;
            event_t event;

            memset(&epoll_event, 0, sizeof(struct epoll_event));
            epoll_event.data.fd = sock;
            epoll_event.events = 0;

            if ((events & POLLER_READ))
                epoll_event.events |= EPOLLIN;

            if ((events & POLLER_WRITE))
                epoll_event.events |= EPOLLOUT;

            if ((events & POLLER_EXCEPT))
                epoll_event.events |= EPOLLERR;

            if (epoll_ctl(_epfd, EPOLL_CTL_ADD, sock, &epoll_event) != 0)
                return -1;
        }

        return base_poller::add(sock, events);
    }

    virtual int remove(socket_t sock, uint32_t events)
    {
        event_t event;

        if (base_poller::remove(sock, events) != 0)
            return -1;

        if (find(sock, event))
        {
            struct epoll_event epoll_event;

            memset(&epoll_event, 0, sizeof(struct epoll_event));

            epoll_event.data.fd = sock;
            epoll_event.events = 0;

            if ((event.events & POLLER_READ))
                epoll_event.events |= EPOLLIN;

            if ((event.events & POLLER_WRITE))
                epoll_event.events |= EPOLLOUT;

            if ((event.events & POLLER_EXCEPT))
                epoll_event.events |= EPOLLERR;

            if (epoll_ctl(_epfd, EPOLL_CTL_MOD, sock, &epoll_event) != 0)
                return -1;
        }
        else
        {
            if (epoll_ctl(_epfd, EPOLL_CTL_DEL, sock, NULL) != 0)
                return -1;
        }

        return 0;
    }

    virtual int wait(std::vector<event_t>& events)
    {
        const int MAX_EPOLL_EVENTS = 1024;
        struct epoll_event epoll_events[MAX_EPOLL_EVENTS];

        events.clear();

        int n = epoll_wait(_epfd, epoll_events, MAX_EPOLL_EVENTS, -1);

        if (n < 0)
            return -1;

        for (int i = 0; i < n; i++)
        {
            const struct epoll_event* p = &epoll_events[i];
            event_t event;

            event.sock = p->data.fd;
            event.events = 0;

            if ((p->events & EPOLLIN))
                event.events |= POLLER_READ;

            if ((p->events & EPOLLOUT))
                event.events |= POLLER_WRITE;

            if ((p->events & EPOLLERR))
                event.events |= POLLER_EXCEPT;

            events.push_back(event);
        }

        return 0;
    }

  private:
    int _epfd;
    std::vector<event_t> _events;
};
#endif

inline poller* poller::create(poller_type_t poller_type)
{
    switch (poller_type)
    {
        case POLLER_TYPE_SELECT:
            return new select_poller();
        case POLLER_TYPE_POLL:
            return new poll_poller();
        case POLLER_TYPE_EPOLL:
            return new epoll_poller();
    }

    return NULL;
}

inline const char* poller::name(poller_type_t poller_type)
{
    switch (poller_type)
    {
        case POLLER_TYPE_SELECT:
            return "select";
        case POLLER_TYPE_POLL:
            return "poll";
        case POLLER_TYPE_EPOLL:
            return "epoll";
    }

    return "none";
}

inline void poller::destroy(poller* poller)
{
    delete poller;
}

#endif /* _POLLER_H */
