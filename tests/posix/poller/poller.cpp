// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "poller.h"
#include <string.h>

//==============================================================================
//
// class poller:
//
//==============================================================================

poller::poller()
{
}

poller::~poller()
{
}

int poller::add(socket_t sock, uint32_t events)
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

int poller::remove(socket_t sock, uint32_t events)
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

const char* poller::name(poller_type_t poller_type)
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

poller* poller::create(poller_type_t poller_type)
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

void poller::destroy(poller* poller)
{
    delete poller;
}

bool poller::find(socket_t sock, event_t& event) const
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

//==============================================================================
//
// class select_poller:
//
//==============================================================================

select_poller::select_poller()
{
}

select_poller::~select_poller()
{
}

int select_poller::wait(std::vector<event_t>& events)
{
    int ret = -1;
    fd_set rfds;
    fd_set wfds;
    fd_set xfds;
    int nfds;
    socket_t max = 0;

    events.clear();

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    for (size_t i = 0; i < _events.size(); i++)
    {
        const event_t& event = _events[i];

        if (event.events & POLLER_READ)
            FD_SET((uint32_t)event.sock, &rfds);

        if (event.events & POLLER_WRITE)
            FD_SET((uint32_t)event.sock, &wfds);

        if (event.events & POLLER_EXCEPT)
            FD_SET((uint32_t)event.sock, &xfds);

        if (event.sock > max)
            max = event.sock;
    }

    if ((nfds = sock_select(max + 1, &rfds, &wfds, &xfds, NULL)) < 0)
        goto done;

    for (socket_t sock = 0; sock < max + 1; sock++)
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

//==============================================================================
//
// class poll_poller:
//
//==============================================================================

#if !defined(WINDOWS_HOST)

poll_poller::poll_poller()
{
}

poll_poller::~poll_poller()
{
}

int poll_poller::wait(std::vector<event_t>& events)
{
    std::vector<struct pollfd> pollfds;

    events.clear();

    for (size_t i = 0; i < _events.size(); i++)
    {
        const event_t& event = _events[i];
        struct pollfd pollfd;

        memset(&pollfd, 0, sizeof(pollfd));

        pollfd.fd = event.sock;

        if (event.events & POLLER_READ)
            pollfd.events |= (POLLIN | POLLRDNORM | POLLRDBAND);

        if (event.events & POLLER_WRITE)
            pollfd.events |= (POLLOUT | POLLWRNORM | POLLWRBAND);

        if (event.events & POLLER_EXCEPT)
            pollfd.events |= (POLLERR | POLLHUP | POLLRDHUP);

        pollfds.push_back(pollfd);
    }

    if (poll(&pollfds[0], pollfds.size(), -1) == -1)
        return -1;

    std::vector<struct pollfd>::iterator p = pollfds.begin();
    std::vector<struct pollfd>::iterator end = pollfds.end();

    for (; p != end; p++)
    {
        struct pollfd& pollfd = *p;
	short revents = pollfd.revents;

	if (!revents)
	{
	    printf("no revents\n");
	    continue;
	}

        if (revents & (POLLIN | POLLRDNORM | POLLRDBAND))
	{
	    revents &= ~(POLLIN | POLLRDNORM | POLLRDBAND);
            events.push_back(event_t(pollfd.fd, POLLER_READ));
	}

        if (revents & (POLLOUT | POLLWRNORM | POLLWRBAND))
	{
            revents &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
            events.push_back(event_t(pollfd.fd, POLLER_WRITE));
	}

        if (revents & (POLLERR | POLLHUP | POLLRDHUP))
	{
            revents &= (POLLERR | POLLHUP | POLLRDHUP);
            events.push_back(event_t(pollfd.fd, POLLER_EXCEPT));
	}

	if (revents)
	{
printf("revents.leftover=%u\n", revents);
	}
    }

    return 0;
}

#endif /* !defined(WINDOWS_HOST) */

//==============================================================================
//
// class epoll_poller:
//
//==============================================================================

#if !defined(WINDOWS_HOST)

epoll_poller::epoll_poller()
{
    _epfd = epoll_create1(0);
}

epoll_poller::~epoll_poller()
{
    close(_epfd);
}

int epoll_poller::add(socket_t sock, uint32_t events)
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

    return poller::add(sock, events);
}

int epoll_poller::remove(socket_t sock, uint32_t events)
{
    event_t event;

    if (poller::remove(sock, events) != 0)
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

int epoll_poller::wait(std::vector<event_t>& events)
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

#endif /* !defined(WINDOWS_HOST) */
