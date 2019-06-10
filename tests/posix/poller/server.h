// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TESTS_LIBCSOCKETS_SERVER_H
#define _OE_TESTS_LIBCSOCKETS_SERVER_H

#include <stdint.h>
#include "poller.h"

extern "C" void run_server(
    uint16_t port,
    size_t num_clients,
    poller_type_t poller_type);

#endif /* _OE_TESTS_LIBCSOCKETS_SERVER_H */
