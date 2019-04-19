// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "client.h"
#include "server.h"

static uint16_t PORT = 12345;

static void* client_thread(void* arg)
{
    run_client(PORT);
    return NULL;
}

static void* server_thread(void* arg)
{
    run_server(PORT);
    return NULL;
}

int main()
{
    pthread_t client;
    pthread_t server;
    void* ret;

    if (pthread_create(&server, NULL, server_thread, NULL) != 0)
    {
        assert("pthread_create()" == NULL);
    }

    sleep(1);

    if (pthread_create(&client, NULL, client_thread, NULL) != 0)
    {
        assert("pthread_create()" == NULL);
    }

    pthread_join(client, &ret);
    pthread_join(server, &ret);

    return 0;
}
