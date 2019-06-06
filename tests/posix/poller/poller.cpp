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

#if !defined(_MSC_VER)

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
            continue;

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
            revents &= ~(POLLERR | POLLHUP | POLLRDHUP);
            events.push_back(event_t(pollfd.fd, POLLER_EXCEPT));
        }

        if (revents)
        {
            printf("%s(): leftover revents: %u\n", __FUNCTION__, revents);
        }
    }

    return 0;
}

#endif /* !defined(_MSC_VER) */
