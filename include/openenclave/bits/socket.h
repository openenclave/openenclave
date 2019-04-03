/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# error openenclave/bits/socket.h should only be included with enclave.h
#endif
#include <openenclave/bits/sockettypes.h>
#include <openenclave/bits/timetypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OE_NETWORK_INSECURE = 0,
    OE_NETWORK_SECURE_HARDWARE = 1
} oe_network_security_t;

typedef void* oe_socket_t;

#ifndef FD_SETSIZE
#define FD_SETSIZE      64
#endif /* FD_SETSIZE */

typedef struct oe_fd_set {
    unsigned int fd_count;             /* how many are SET? */
    oe_socket_t fd_array[FD_SETSIZE];  /* an array of SOCKETs */
} oe_fd_set;

typedef struct oe_provider_fd_set {
    unsigned int fd_count;             /* how many are SET? */
    intptr_t fd_array[FD_SETSIZE];     /* an array of SOCKETs */
} oe_provider_fd_set;


typedef uint16_t oe_sa_family_t;

typedef int oe_socklen_t;

typedef struct oe_addrinfo {
    int                 ai_flags;
    int                 ai_family;
    int                 ai_socktype;
    int                 ai_protocol;
    size_t              ai_addrlen;
    char*               ai_canonname;
    struct oe_sockaddr* ai_addr;
    struct oe_addrinfo* ai_next;
} oe_addrinfo;

typedef struct oe_sockaddr {
    oe_sa_family_t sa_family;
    char           sa_data[14];
} oe_sockaddr;

#ifndef _SS_MAXSIZE
# define _SS_MAXSIZE   128
# define _SS_ALIGNSIZE (sizeof(int64_t))
# define _SS_PAD1SIZE  (_SS_ALIGNSIZE - sizeof(oe_sa_family_t))
# define _SS_PAD2SIZE  (_SS_MAXSIZE - (sizeof(oe_sa_family_t) + _SS_PAD1SIZE + _SS_ALIGNSIZE))
#endif
#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN  22
#endif
#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 65
#endif

typedef struct oe_sockaddr_storage {
    oe_sa_family_t ss_family;
    char           __ss_pad1[_SS_PAD1SIZE];
    int64_t        __ss_align;
    char           __ss_pad2[_SS_PAD2SIZE];
} oe_sockaddr_storage;

typedef struct oe_in_addr {
    uint32_t    s_addr;
} oe_in_addr;

#ifndef INADDR_ANY
# define INADDR_ANY  0x00000000
#endif
#ifndef INADDR_NONE
# define INADDR_NONE 0xffffffff
#endif
#ifndef IN6_IS_ADDR_V4MAPPED
# define IN6_IS_ADDR_V4MAPPED(a) \
    (((a)->s6_words[0] == 0) &&  \
     ((a)->s6_words[1] == 0) &&  \
     ((a)->s6_words[2] == 0) &&  \
     ((a)->s6_words[3] == 0) &&  \
     ((a)->s6_words[4] == 0) &&  \
     ((a)->s6_words[5] == 0xffff))
#endif

typedef struct oe_sockaddr_in {
    oe_sa_family_t sin_family;
    uint16_t       sin_port;
    oe_in_addr     sin_addr;
} oe_sockaddr_in;

typedef struct oe_in6_addr {
    union {
        uint8_t  Byte[16];
        uint16_t Word[8];
    } u;
} oe_in6_addr;

#ifndef s6_addr
# define s6_addr u.Byte
#endif
#ifndef s6_words
# define s6_words u.Word
#endif

#ifndef IN6ADDR_LOOPBACK_INIT
# define IN6ADDR_LOOPBACK_INIT { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#endif

typedef struct oe_sockaddr_in6 {
    oe_sa_family_t sin6_family;
    uint16_t       sin6_port;
    uint32_t       sin6_flowinfo;
    oe_in6_addr    sin6_addr;
    uint32_t       sin6_scope_id;
} oe_sockaddr_in6;

int oe_fd_isset(_In_ oe_socket_t fd, _In_ oe_fd_set* set);

#define OE_SOCKET_ERROR -1
#define OE_INVALID_SOCKET   (oe_socket_t)(~0)
#define OE_IPV6_V6ONLY      27
#define OE_IPPROTO_IPV6     41
#define OE_IPPROTO_TCP       6
#define OE_MSG_WAITALL     0x8
#define OE_SOL_SOCKET   0xffff
#define OE_SO_SNDBUF    0x1001
#define OE_SO_RCVBUF    0x1002
#define OE_SO_KEEPALIVE 0x0008
#define OE_SO_ERROR     0x1007
#define OE_TCP_NODELAY       1
#define OE_TCP_KEEPALIVE     3
#define OE_SOMAXCONN    0x7fffffff

#define OE_IOCPARM_MASK   0x7f
#define OE_IOC_IN       0x80000000
#define OE_IOW(x,y,t)   (OE_IOC_IN|(((long)sizeof(t)&OE_IOCPARM_MASK)<<16)|((x)<<8)|(y))
#define OE_FIONBIO      OE_IOW('f', 126, u_long)

#define OE_AI_PASSIVE      0x00000001
#define OE_AI_CANONNAME    0x00000002
#define OE_AI_NUMERICHOST  0x00000004
#define OE_AI_ALL          0x00000100
#define OE_AI_ADDRCONFIG   0x00000400
#define OE_AI_V4MAPPED     0x00000800

#define OE_NI_NOFQDN       0x01
#define OE_NI_NUMERICHOST  0x02
#define OE_NI_NAMEREQD     0x04
#define OE_NI_NUMERICSERV  0x08
#define OE_NI_DGRAM        0x10
#define OE_NI_MAXHOST      1025
#define OE_NI_MAXSERV      32

#ifndef OE_NO_POSIX_SOCKET_API
/* Map standard socket API names to the OE equivalents. */
# define accept            oe_accept
# define addrinfo          oe_addrinfo
# define AI_PASSIVE        OE_AI_PASSIVE
# define AI_CANONNAME      OE_AI_CANONNAME
# define AI_NUMERICHOST    OE_AI_NUMERICHOST
# define AI_ALL            OE_AI_ALL
# define AI_ADDRCONFIG     OE_AI_ADDRCONFIG
# define AI_V4MAPPED       OE_AI_V4MAPPED
# define AF_INET           OE_AF_INET
# define AF_INET6          OE_AF_INET6
# define bind              oe_bind
# define connect           oe_connect
# define FD_ISSET(fd, set) oe_fd_isset((oe_socket_t)(fd), (oe_fd_set*)(set))
# define fd_set            oe_fd_set
# define FIONBIO           OE_FIONBIO
# define freeaddrinfo      oe_freeaddrinfo
# define getpeername       oe_getpeername
# define getsockname       oe_getsockname
# define getsockopt        oe_getsockopt
# define htonl             oe_htonl
# define htons             oe_htons
# define in_addr           oe_in_addr
# define in6_addr          oe_in6_addr
# define inet_addr         oe_inet_addr
# define INVALID_SOCKET    OE_INVALID_SOCKET
# define IPV6_V6ONLY       OE_IPV6_V6ONLY
# define IPPROTO_IPV6      OE_IPPROTO_IPV6
# define IPPROTO_TCP       OE_IPPROTO_TCP
# define listen            oe_listen
# define MSG_WAITALL       OE_MSG_WAITALL
# define NI_NOFQDN         OE_NI_NOFQDN
# define NI_NUMERICHOST    OE_NI_NUMERICHOST
# define NI_NAMEREQD       OE_NI_NAMEREQD
# define NI_NUMERICSERV    OE_NI_NUMERICSERV
# define NI_DGRAM          OE_NI_DGRAM
# define NI_MAXHOST        OE_NI_MAXHOST
# define NI_MAXSERV        OE_NI_MAXSERV
# define ntohl             oe_ntohl
# define ntohs             oe_ntohs
# define recv              oe_recv
# define select            oe_select
# define send              oe_send
# define setsockopt        oe_setsockopt
# define shutdown          oe_shutdown
# define SOCK_STREAM       OE_SOCK_STREAM
# define sockaddr          oe_sockaddr
# define sockaddr_in       oe_sockaddr_in
# define sockaddr_in6      oe_sockaddr_in6
# define sockaddr_storage  oe_sockaddr_storage
# define socklen_t         oe_socklen_t
# define SOCKET            oe_socket_t
# define SOL_SOCKET        OE_SOL_SOCKET
# define SO_ERROR          OE_SO_ERROR
# define SO_KEEPALIVE      OE_SO_KEEPALIVE
# define SO_RCVBUF         OE_SO_RCVBUF
# define SO_SNDBUF         OE_SO_SNDBUF
# define SOMAXCONN         OE_SOMAXCONN
# define TCP_KEEPALIVE     OE_TCP_KEEPALIVE
# define TCP_NODELAY       OE_TCP_NODELAY
#endif

#ifndef OE_NO_WINSOCK_API
/* Map Winsock APIs to the OE equivalents. */
# define closesocket       oe_closesocket
# define ioctlsocket       oe_ioctlsocket
# define SOCKET_ERROR      OE_SOCKET_ERROR
# define WSADATA           oe_wsa_data_t
# define WSAECONNABORTED   OE_ECONNABORTED
# define WSAECONNRESET     OE_ECONNRESET
# define WSAEINPROGRESS    OE_EINPROGRESS
# define WSAEWOULDBLOCK    OE_EAGAIN
#endif

oe_socket_t
oe_accept(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
    _Inout_ int *addrlen);

int
oe_bind(
    _In_ oe_socket_t s,
    _In_reads_bytes_(namelen) const oe_sockaddr* name,
    int namelen);

int
oe_closesocket(
    _In_ oe_socket_t s);

int
oe_connect(
    _In_ oe_socket_t s,
    _In_reads_bytes_(namelen) const oe_sockaddr* name,
    int namelen);

void
oe_freeaddrinfo(
    _In_ oe_addrinfo* ailist);

int
oe_getaddrinfo_OE_NETWORK_INSECURE(
    _In_z_ const char* node,
    _In_z_ const char* service,
    _In_ const oe_addrinfo* hints,
    _Out_ oe_addrinfo** res);

int
oe_getaddrinfo_OE_SECURE_HARDWARE(
    _In_z_ const char* node,
    _In_z_ const char* service,
    _In_ const oe_addrinfo* hints,
    _Out_ oe_addrinfo** res);

#define oe_getaddrinfo(network_security, node, service, hints, res) \
    oe_getaddrinfo_ ## network_security((node), (service), (hints), (res))

#ifdef OE_SECURE_POSIX_NETWORK_API
#define getaddrinfo(node, service, hints, res) \
    oe_getaddrinfo(OE_NETWORK_SECURE_HARDWARE, node, service, hints, res)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define getaddrinfo(node, service, hints, res) \
    oe_getaddrinfo(OE_NETWORK_INSECURE, node, service, hints, res)
#endif

int
oe_gethostname_OE_NETWORK_INSECURE(
    _Out_writes_(len) char* name,
    _In_ size_t len);

int
oe_gethostname_OE_SECURE_HARDWARE(
    _Out_writes_(len) char* name,
    _In_ size_t len);

#define oe_gethostname(network_security, name, len) \
    oe_gethostname_ ## network_security((name), (len))

#ifdef OE_SECURE_POSIX_NETWORK_API
#define gethostname(name, len) \
    oe_gethostname(OE_NETWORK_SECURE_HARDWARE, name, len)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define gethostname(name, len) \
    oe_gethostname(OE_NETWORK_INSECURE, name, len)
#endif

int
oe_getnameinfo_OE_NETWORK_INSECURE(
    _In_ const struct oe_sockaddr *sa,
    _In_ oe_socklen_t salen,
    _Out_writes_opt_z_(hostlen) char* host,
    _In_ size_t hostlen,
    _Out_writes_opt_z_(servlen) char* serv,
    _In_ size_t servlen,
    _In_ int flags);

int
oe_getnameinfo_OE_NETWORK_SECURE_HARDWARE(
    _In_ const struct oe_sockaddr *sa,
    _In_ oe_socklen_t salen,
    _Out_writes_opt_z_(hostlen) char* host,
    _In_ size_t hostlen,
    _Out_writes_opt_z_(servlen) char* serv,
    _In_ size_t servlen,
    _In_ int flags);

#ifdef OE_SECURE_POSIX_NETWORK_API
#define getnameinfo(sa, salen, host, hostlen, serv, servlen, flags) \
    oe_getnameinfo(OE_NETWORK_SECURE_HARDWARE, sa, salen, host, hostlen, serv, servlen, flags)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define getnameinfo(sa, salen, host, hostlen, serv, servlen, flags) \
    oe_getnameinfo(OE_NETWORK_INSECURE, sa, salen, host, hostlen, serv, servlen, flags)
#endif

int
oe_getpeername(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
    _Inout_ int *addrlen);

int
oe_getsockname(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
    _Inout_ int *addrlen);

int
oe_getsockopt(
    _In_ oe_socket_t s,
    _In_ int level,
    _In_ int optname,
    _Out_writes_(*optlen) char* optval,
    _Inout_ oe_socklen_t* optlen);

uint32_t
oe_htonl(
    _In_ uint32_t hostLong);

uint16_t
oe_htons(
    _In_ uint16_t hostShort);

uint32_t
oe_inet_addr(
    _In_z_ const char* cp);

int
oe_ioctlsocket(
    _In_ oe_socket_t s,
    _In_ long cmd,
    _Inout_ unsigned long *argp);

int
oe_listen(
    _In_ oe_socket_t s,
    _In_ int backlog);

uint32_t
oe_ntohl(
    _In_ uint32_t netLong);

uint16_t
oe_ntohs(
    _In_ uint16_t netShort);

ssize_t
oe_recv(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(len) void* buf,
    _In_ size_t len,
    _In_ int flags);

int
oe_select(
    _In_ int nfds,
    _Inout_opt_ oe_fd_set* readfds,
    _Inout_opt_ oe_fd_set* writefds,
    _Inout_opt_ oe_fd_set* exceptfds,
    _In_opt_ const struct timeval* timeout);

int
oe_send(
    _In_ oe_socket_t s,
    _In_reads_bytes_(len) const char* buf,
    _In_ int len,
    _In_ int flags);

int
oe_setsockopt(
    _In_ oe_socket_t s,
    _In_ int level,
    _In_ int optname,
    _In_reads_bytes_(optlen) const char* optval,
    _In_ oe_socklen_t optlen);

int
oe_shutdown(
    _In_ oe_socket_t s,
    _In_ int how);

oe_socket_t
oe_socket_OE_NETWORK_INSECURE(
    _In_ int domain,
    _In_ int type,
    _In_ int protocol);

oe_socket_t
oe_socket_OE_NETWORK_SECURE_HARDWARE(
    _In_ int domain,
    _In_ int type,
    _In_ int protocol);

#define oe_socket(network_security, domain, type, protocol) \
    oe_socket_ ## network_security((domain), (type), (protocol))

#ifdef OE_SECURE_POSIX_NETWORK_API
#define socket(domain, type, protocol) \
     oe_socket(OE_NETWORK_SECURE_HARDWARE, domain, type, protocol)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define socket(domain, type, protocol) \
     oe_socket(OE_NETWORK_INSECURE, domain, type, protocol)
#endif

typedef struct {
    int unused;
} oe_wsa_data_t;

int oe_wsa_cleanup_OE_NETWORK_INSECURE(void);
int oe_wsa_cleanup_OE_NETWORK_SECURE_HARDWARE(void);

#define oe_wsa_cleanup(network_security) oe_wsa_cleanup_ ## network_security()

#ifdef OE_SECURE_POSIX_NETWORK_API
#define WSACleanup() \
     oe_wsa_cleanup(OE_NETWORK_SECURE_HARDWARE)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define WSACleanup() \
     oe_wsa_cleanup(OE_NETWORK_INSECURE)
#endif

int oe_wsa_get_last_error_OE_NETWORK_INSECURE(void);
int oe_wsa_get_last_error_OE_NETWORK_SECURE_HARDWARE(void);

#define oe_wsa_get_last_error(network_security) oe_wsa_get_last_error_ ## network_security()

#ifdef OE_SECURE_POSIX_NETWORK_API
#define WSAGetLastError() \
     oe_wsa_get_last_error(OE_NETWORK_SECURE_HARDWARE)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define WSAGetLastError() \
     oe_wsa_get_last_error(OE_NETWORK_INSECURE)
#endif

void oe_wsa_set_last_error_OE_NETWORK_INSECURE(_In_ int error);
void oe_wsa_set_last_error_OE_NETWORK_SECURE_HARDWARE(_In_ int error);

#define oe_wsa_set_last_error(network_security, error) oe_wsa_set_last_error_ ## network_security(error)

#ifdef OE_SECURE_POSIX_NETWORK_API
#define WSASetLastError(error) \
     oe_wsa_set_last_error(OE_NETWORK_SECURE_HARDWARE, error)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define WSASetLastError(error) \
     oe_wsa_set_last_error(OE_NETWORK_INSECURE, error)
#endif

int oe_wsa_startup_OE_NETWORK_INSECURE(
    _In_ uint16_t version_required,
    _Out_ oe_wsa_data_t* wsa_data);

int oe_wsa_startup_OE_NETWORK_SECURE_HARDWARE(
    _In_ uint16_t version_required,
    _Out_ oe_wsa_data_t* wsa_data);

#define oe_wsa_startup(network_security, version_required, wsa_data) \
    oe_wsa_startup_ ## network_security((version_required), (wsa_data))

#ifdef OE_SECURE_POSIX_NETWORK_API
#define WSAStartup(version_required, wsa_data) \
     oe_wsa_startup(OE_NETWORK_SECURE_HARDWARE, version_required, wsa_data)
#elif !defined(OE_NO_POSIX_SOCKET_API)
#define WSAStartup(version_required, wsa_data) \
     oe_wsa_startup(OE_NETWORK_INSECURE, version_required, wsa_data)
#endif

typedef struct {
    intptr_t (*s_accept)(_In_ intptr_t provider_socket,
                      _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
                      _Inout_ int *addrlen);
    int (*s_bind)(_In_ intptr_t provider_socket,
                  _In_reads_bytes_(namelen) const oe_sockaddr* name,
                  int namelen);
    int (*s_close)(_In_ intptr_t provider_socket);
    int (*s_connect)(_In_ intptr_t provider_socket,
                     _In_reads_bytes_(namelen) const oe_sockaddr* name,
                     int namelen);
    int (*s_getpeername)(_In_ intptr_t provider_socket,
                         _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
                        _Inout_ int *addrlen);
    int (*s_getsockname)(_In_ intptr_t provider_socket,
                         _Out_writes_bytes_(*addrlen) struct oe_sockaddr* addr,
                         _Inout_ int *addrlen);
    int (*s_getsockopt)(_In_ intptr_t provider_socket,
                        int level,
                        int optname,
                        _Out_writes_(*optlen) char* optval,
                        _Inout_ oe_socklen_t* optlen);
    int (*s_ioctl)(_In_ intptr_t provider_socket,
                   long cmd,
                   _Inout_ unsigned long *argp);
    int (*s_listen)(_In_ intptr_t provider_socket,
                    int backlog);
    ssize_t (*s_recv)(_In_ intptr_t provider_socket,
                      _Out_writes_bytes_(len) void* buf,
                      size_t len,
                      int flags);
    int (*s_select)(_In_ int nfds,
                    _Inout_opt_ oe_provider_fd_set* readfds,
                    _Inout_opt_ oe_provider_fd_set* writefds,
                    _Inout_opt_ oe_provider_fd_set* exceptfds,
                    _In_opt_ const struct timeval* timeout);
    int (*s_send)(_In_ intptr_t provider_socket,
                  _In_reads_bytes_(len) const char* buf,
                  int len,
                  int flags);
    int (*s_setsockopt)(_In_ intptr_t provider_socket,
                        int level,
                        int optname,
                        _In_reads_bytes_(optlen) const char* optval,
                        oe_socklen_t optlen);
    int (*s_shutdown)(_In_ intptr_t provider_socket,
                      int how);
} oe_socket_provider_t;

oe_socket_t oe_register_socket(
    _In_ const oe_socket_provider_t* provider,
    intptr_t provider_socket);

#ifdef __cplusplus
}
#endif
