// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../common/hostresolvargs.h"

void (*oe_handle_hostresolver_ocall_callback)(void*);

static void _handle_hostresolver_ocall(void* args_)
{
    oe_hostresolv_args_t* args = (oe_hostresolv_args_t*)args_;

    /* ATTN: handle errno propagation. */

    if (!args)
        return;

    args->err = 0;
    switch (args->op)
    {
        case OE_HOSTRESOLV_OP_GETADDRINFO:
        {
            // int32_t buffer_len;
            // int32_t nodelen;
            // int32_t servicelen;

            struct addrinfo hints = {
                .ai_flags = args->u.getaddrinfo.hint_flags,
                .ai_family = args->u.getaddrinfo.hint_family,
                .ai_socktype = args->u.getaddrinfo.hint_socktype,
                .ai_protocol = args->u.getaddrinfo.hint_protocol,
                .ai_addr = NULL,
                .ai_canonname = NULL,
                .ai_next = NULL,
            };

            struct addrinfo* result = NULL;
            const char* node =
                (const char*)((args->u.getaddrinfo.nodelen > 0) ? args->buf : NULL);
            const char *service = (const char*)((args->u.getaddrinfo.servicelen > 0)? args->buf+args->u.getaddrinfo.nodelen: NULL);

            args->u.getaddrinfo.ret =
                getaddrinfo(node, service, &hints, &result);

            if (args->u.getaddrinfo.ret == 0)
            {
                struct addrinfo* thisinfo = result;
                size_t buffer_required = (size_t)0;
                size_t buffer_available =
                    (size_t)args->u.getaddrinfo.buffer_len;

                // If we had a good return, check to see we can fit the result
                // into the buffer given. Return EAI_OVERFLOW if not.
                do
                {
                    buffer_required += sizeof(struct addrinfo);
                    if (thisinfo->ai_addr)
                    {
                        buffer_required += sizeof(struct sockaddr);
                    }
                    if (thisinfo->ai_canonname)
                    {
                        buffer_required += strlen(thisinfo->ai_canonname) + 1;
                    }

                    thisinfo = thisinfo->ai_next;
                } while (thisinfo != NULL);

                if (buffer_required > buffer_available)
                {
                    args->u.getaddrinfo.ret = EAI_OVERFLOW;
                    args->u.getaddrinfo.buffer_len = (int32_t)buffer_required;
                }
                else
                {
                    size_t canon_namelen = 0;
                    uint8_t* bufptr = args->buf;
                    thisinfo = result;
                    do
                    {
                        // Set up the pointers in the destination structure to
                        // point at the buffer after the addrinfo structure.
                        struct addrinfo* buf_info = (struct addrinfo*)bufptr;
                        buf_info->ai_flags = thisinfo->ai_flags;
                        buf_info->ai_family = thisinfo->ai_family;
                        buf_info->ai_socktype = thisinfo->ai_socktype;
                        buf_info->ai_protocol = thisinfo->ai_protocol;
                        buf_info->ai_addrlen = thisinfo->ai_addrlen;
                        buf_info->ai_canonname = NULL;
                        buf_info->ai_addr = NULL;
                        buf_info->ai_next = NULL;

                        bufptr += sizeof(struct addrinfo);
                        if (thisinfo->ai_addr)
                        {
                            buf_info->ai_addr = (struct sockaddr*)(bufptr);
                            memcpy(
                                buf_info->ai_addr,
                                thisinfo->ai_addr,
                                buf_info->ai_addrlen);
                            bufptr += buf_info->ai_addrlen;
                        }
                        if (thisinfo->ai_canonname)
                        {
                            canon_namelen = strlen(thisinfo->ai_canonname) + 1;
                            buf_info->ai_canonname = (char*)bufptr;
                            memcpy(
                                buf_info->ai_canonname,
                                thisinfo->ai_canonname,
                                canon_namelen);
                            bufptr += canon_namelen;
                        }

                        thisinfo = thisinfo->ai_next;
                        if (thisinfo)
                        {
                            buf_info->ai_next = (struct addrinfo*)bufptr;
                        }

                    } while (thisinfo != NULL);
                    freeaddrinfo(result);
                }
            }
            break;
        }
        case OE_HOSTRESOLV_OP_GETNAMEINFO:
        {
            const struct sockaddr* addr =
                (args->u.getnameinfo.addrlen > 0)
                    ? (const struct sockaddr*)(args->buf)
                    : NULL;
            char* hostname =
                (args->u.getnameinfo.hostlen > 0) ? (char*)(args->buf) : NULL;
            char* servicename =
                (args->u.getnameinfo.servlen > 0)
                    ? (char*)(args->buf + args->u.getnameinfo.hostlen)
                    : NULL;
            args->u.getnameinfo.ret = getnameinfo(
                addr,
                (socklen_t)args->u.getnameinfo.addrlen,
                hostname,
                (socklen_t)args->u.getnameinfo.hostlen,
                servicename,
                (socklen_t)args->u.getnameinfo.servlen,
                args->u.getnameinfo.flags);
            break;
        }
        case OE_HOSTRESOLV_OP_SHUTDOWN:
        {
            // 2do
            break;
        }
        default:
        {
            // Invalid
            break;
        }
    }
    args->err = errno;
}

void oe_resolver_install_hostresolver(void)
{
    oe_handle_hostresolver_ocall_callback = _handle_hostresolver_ocall;
}
