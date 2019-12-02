// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <netinet/in.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>

static const uint16_t _port = 12347;
static sockaddr_in _addr;
static int _epfd;
static int _sockfd;

extern "C" void set_up()
{
    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    OE_TEST(oe_load_module_host_epoll() == OE_OK);

    _addr.sin_family = AF_INET;
    _addr.sin_port = htons(_port);
    _addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // create and bind UDP socket
    _sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    OE_TEST(_sockfd >= 0);
    OE_TEST(
        bind(_sockfd, reinterpret_cast<sockaddr*>(&_addr), sizeof _addr) == 0);

    // create epoll instance
    _epfd = epoll_create(1);
    OE_TEST(_epfd >= 0);
}

extern "C" void tear_down()
{
    OE_TEST(close(_epfd) == 0);
    OE_TEST(close(_sockfd) == 0);
}

extern "C" void wait_for_events()
{
    uint8_t run = 1;

    while (run)
    {
        epoll_event event{};

        int n;
        do
        {
            n = epoll_wait(_epfd, &event, 1, -1);
        } while (n == -1 && errno == EINTR);

        if (n == 1)
        {
            OE_TEST(event.data.fd == _sockfd);
            OE_TEST(read(_sockfd, &run, sizeof run) == sizeof run);
        }
        else
            OE_TEST(n == 0); // fd has been deleted
    }
}

static void _send(uint8_t run)
{
    const int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    OE_TEST(sockfd >= 0);
    OE_TEST(
        connect(sockfd, reinterpret_cast<sockaddr*>(&_addr), sizeof _addr) ==
        0);
    OE_TEST(write(sockfd, &run, sizeof run) == sizeof run);
    OE_TEST(close(sockfd) == 0);
}

extern "C" void trigger_and_add_event()
{
    _send(1);

    // add fd to the epoll instance
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = _sockfd;
    OE_TEST(epoll_ctl(_epfd, EPOLL_CTL_ADD, _sockfd, &event) == 0);
}

extern "C" void trigger_and_delete_event()
{
    _send(1);

    // delete fd from the epoll instance
    OE_TEST(epoll_ctl(_epfd, EPOLL_CTL_DEL, _sockfd, nullptr) == 0);
}

extern "C" void cancel_wait()
{
    // add fd to the epoll instance
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = _sockfd;
    OE_TEST(epoll_ctl(_epfd, EPOLL_CTL_ADD, _sockfd, &event) == 0);

    _send(0);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    9);   /* TCSCount */
