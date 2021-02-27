// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

static void cb_listen(
    struct evconnlistener* listener,
    evutil_socket_t fd,
    struct sockaddr* sa,
    int socklen,
    void* user_data);
static void cb_connect(struct bufferevent* bev, short events, void* user_data);
static void cb_read(struct bufferevent* bev, void* ctx);

struct bufferevent* bev;
bool exit_after_one_message = false;

int main(int argc, char** argv)
{
    struct event_base* base;
    struct evconnlistener* listener;
    struct sockaddr_in sin = {0};

    if (argc == 2 && strcmp(argv[1], "--once") == 0)
        exit_after_one_message = true;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(12345);

    base = event_base_new();
    OE_TEST(base != NULL);

    listener = evconnlistener_new_bind(
        base,
        cb_listen,
        (void*)base,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
        -1,
        (struct sockaddr*)&sin,
        sizeof(sin));
    OE_TEST(listener != NULL);

    event_base_dispatch(base);
    bufferevent_free(bev);
    evconnlistener_free(listener);
    event_base_free(base);

    return 0;
}

static void cb_listen(
    struct evconnlistener* listener,
    evutil_socket_t fd,
    struct sockaddr* sa,
    int socklen,
    void* user_data)
{
    struct event_base* base = (struct event_base*)user_data;

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    OE_TEST(bev != NULL);

    bufferevent_setcb(bev, cb_read, NULL, cb_connect, NULL);
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_enable(bev, EV_READ);
}

static void cb_connect(struct bufferevent* bev, short events, void* user_data)
{
    if (events & BEV_EVENT_EOF)
    {
        printf("Connection closed.\n");
    }
    else if (events & BEV_EVENT_ERROR)
    {
        printf("Got an error on the connection: %s\n", strerror(errno));
    }
    /* None of the other events can happen here, since we haven't enabled
     * timeouts */
    bufferevent_free(bev);
}

void cb_read(struct bufferevent* bev, void* ctx)
{
    char* line = NULL;
    size_t n = 0;

    struct evbuffer* input = bufferevent_get_input(bev);
    struct evbuffer* output = bufferevent_get_output(bev);

    const char* prompt = "enclave says: ";
    int prompt_len = strlen(prompt);
    bool exit = false;
    bool received = false;
    while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF)))
    {
        exit = exit || strncmp(line, "exit", 4) == 0;
        evbuffer_add(output, prompt, prompt_len);
        evbuffer_add(output, line, n);
        evbuffer_add(output, "\n", 1);
        printf("received: %s\n", line);
        free(line);
        received = true;
    }

    if (exit || (received && exit_after_one_message))
        event_base_loopexit(bufferevent_get_base(bev), NULL);
}
