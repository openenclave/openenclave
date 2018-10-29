/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <pthread.h>
#include <tee_client_api_extensions.h>
#include "optee-shared.h"

struct tcps_optee_context {
    TEEC_Context ctx;
    TEEC_Session session;
    pthread_t rpc_thread;
    pthread_mutex_t mutex;
    optee_ocall_table_t* ocall_table;
};
