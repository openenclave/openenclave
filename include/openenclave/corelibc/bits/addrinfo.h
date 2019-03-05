// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

int ai_flags;                /* Input flags.  */
int ai_family;               /* Protocol family for socket.  */
int ai_socktype;             /* Socket type.  */
int ai_protocol;             /* Protocol for socket.  */
socklen_t ai_addrlen;        /* Length of socket address.  */
struct oe_sockaddr* ai_addr; /* Socket address for socket.  */
char* ai_canonname;          /* Canonical name for service location.  */
struct oe_addrinfo* ai_next; /* Pointer to next in list.  */
