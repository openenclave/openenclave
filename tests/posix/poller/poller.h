// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _POLLER_H
#define _POLLER_H

#if defined(WINDOWS_HOST)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <vector>

#define POLLER_READ 1
#define POLLER_WRITE 2
#define POLLER_EXCEPT 4

typedef struct _event
{
    int sock;
    uint32_t events;
} event_t;

class poller
{
  public:
    poller() : _max(0)
    {
        memset(&_rfds, 0, sizeof(_rfds));
        memset(&_wfds, 0, sizeof(_wfds));
        memset(&_xfds, 0, sizeof(_xfds));
        FD_ZERO(&_rfds);
        FD_ZERO(&_wfds);
        FD_ZERO(&_xfds);
    }

    ~poller()
    {
    }

    int add(socket_t sock, uint32_t events)
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

    int remove(socket_t sock, uint32_t events)
    {
        if ((events & POLLER_READ))
            FD_CLR((uint32_t)sock, &_rfds);

        if ((events & POLLER_WRITE))
            FD_CLR((uint32_t)sock, &_wfds);

        if ((events & POLLER_EXCEPT))
            FD_CLR((uint32_t)sock, &_xfds);

        return 0;
    }

    int wait(std::vector<event_t>& events)
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

        if ((nfds = select(_max + 1, &rfds, &wfds, &xfds, NULL)) < 0)
            goto done;

        for (socket_t sock = 0; sock < _max + 1; sock++)
        {
            if (FD_ISSET((uint32_t)sock, &rfds))
            {
                event_t event = {sock, POLLER_READ};
                events.push_back(event);
            }

            if (FD_ISSET((uint32_t)sock, &wfds))
            {
                event_t event = {sock, POLLER_WRITE};
                events.push_back(event);
            }

            if (FD_ISSET((uint32_t)sock, &xfds))
            {
                event_t event = {sock, POLLER_EXCEPT};
                events.push_back(event);
            }
        }

        ret = 0;

    done:
        return ret;
    }

    void dump(void)
    {
        printf("*** poller::dump()\n");

        printf("_max=%d\n", _max);

        for (socket_t sock = 0; sock < _max + 1; sock++)
        {
            if (FD_ISSET((uint32_t)sock, &_rfds))
                printf("RD{%d}\n", sock);

            if (FD_ISSET((uint32_t)sock, &_wfds))
                printf("WR{%d}\n", sock);

            if (FD_ISSET((uint32_t)sock, &_xfds))
                printf("EX{%d}\n", sock);
        }
    }

  private:
    fd_set _rfds;
    fd_set _wfds;
    fd_set _xfds;
    socket_t _max;
};

#endif /* _POLLER_H */
