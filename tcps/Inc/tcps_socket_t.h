/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_socket_t.h should only be included with TRUSTED_CODE
#endif
#include "tcps_time_t.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* TCPS_SOCKET;

#ifndef FD_SETSIZE
#define FD_SETSIZE      64
#endif /* FD_SETSIZE */

typedef struct Tcps_fd_set {
    unsigned int fd_count;             /* how many are SET? */
    TCPS_SOCKET  fd_array[FD_SETSIZE]; /* an array of SOCKETs */
} Tcps_fd_set;

typedef uint16_t Tcps_sa_family_t;

typedef int Tcps_socklen_t;

typedef struct Tcps_addrinfo {
    int                   ai_flags;
    int                   ai_family;
    int                   ai_socktype;
    int                   ai_protocol;
    size_t                ai_addrlen;
    char*                 ai_canonname;
    struct Tcps_sockaddr* ai_addr;
    struct Tcps_addrinfo* ai_next;
} Tcps_addrinfo;

typedef struct Tcps_sockaddr {
    Tcps_sa_family_t sa_family;
    char             sa_data[14];
} Tcps_sockaddr;

#ifndef _SS_MAXSIZE
# define _SS_MAXSIZE   128
# define _SS_ALIGNSIZE (sizeof(int64_t))
# define _SS_PAD1SIZE  (_SS_ALIGNSIZE - sizeof(Tcps_sa_family_t))
# define _SS_PAD2SIZE  (_SS_MAXSIZE - (sizeof(Tcps_sa_family_t) + _SS_PAD1SIZE + _SS_ALIGNSIZE))
#endif
#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN  22
#endif
#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 65
#endif

typedef struct Tcps_sockaddr_storage {
    Tcps_sa_family_t ss_family;
    char             __ss_pad1[_SS_PAD1SIZE];
    int64_t          __ss_align;
    char             __ss_pad2[_SS_PAD2SIZE];
} Tcps_sockaddr_storage;

typedef struct Tcps_in_addr {
    uint32_t    s_addr;
} Tcps_in_addr;

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

typedef struct Tcps_sockaddr_in {
    Tcps_sa_family_t sin_family;
    uint16_t         sin_port;
    Tcps_in_addr     sin_addr;
} Tcps_sockaddr_in;

typedef struct Tcps_in6_addr {
    union {
        uint8_t  Byte[16];
        uint16_t Word[8];
    } u;
} Tcps_in6_addr;

#ifndef s6_addr
# define s6_addr u.Byte
#endif
#ifndef s6_words
# define s6_words u.Word
#endif

#ifndef IN6ADDR_LOOPBACK_INIT
# define IN6ADDR_LOOPBACK_INIT { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#endif

typedef struct Tcps_sockaddr_in6 {
    Tcps_sa_family_t sin6_family;
    uint16_t         sin6_port;
    uint32_t         sin6_flowinfo;
    Tcps_in6_addr    sin6_addr;
    uint32_t         sin6_scope_id;
} Tcps_sockaddr_in6;

#include "TcpsTls.h"

int Tcps_FDIsSet(_In_ TCPS_SOCKET fd, _In_ Tcps_fd_set* set);

#define TCPS_SOCKET_ERROR -1
#define TCPS_INVALID_SOCKET  (TCPS_SOCKET)(~0)
#define TCPS_IPV6_V6ONLY      27
#define TCPS_IPPROTO_IPV6     41
#define TCPS_IPPROTO_TCP       6
#define TCPS_MSG_WAITALL     0x8
#define TCPS_SOL_SOCKET   0xffff
#define TCPS_SO_SNDBUF    0x1001
#define TCPS_SO_RCVBUF    0x1002
#define TCPS_SO_KEEPALIVE 0x0008
#define TCPS_SO_ERROR     0x1007
#define TCPS_TCP_NODELAY       1
#define TCPS_TCP_KEEPALIVE     3
#define TCPS_SOMAXCONN    0x7fffffff

#define TCPS_IOCPARM_MASK   0x7f
#define TCPS_IOC_IN       0x80000000
#define TCPS_IOW(x,y,t)   (TCPS_IOC_IN|(((long)sizeof(t)&TCPS_IOCPARM_MASK)<<16)|((x)<<8)|(y))
#define TCPS_FIONBIO      TCPS_IOW('f', 126, u_long)

#define TCPS_AI_PASSIVE      0x00000001
#define TCPS_AI_CANONNAME    0x00000002
#define TCPS_AI_NUMERICHOST  0x00000004
#define TCPS_AI_ALL          0x00000100
#define TCPS_AI_ADDRCONFIG   0x00000400
#define TCPS_AI_V4MAPPED     0x00000800

#define TCPS_NI_NOFQDN       0x01
#define TCPS_NI_NUMERICHOST  0x02
#define TCPS_NI_NAMEREQD     0x04
#define TCPS_NI_NUMERICSERV  0x08
#define TCPS_NI_DGRAM        0x10
#define TCPS_NI_MAXHOST      1025
#define TCPS_NI_MAXSERV      32

#ifndef NO_EXPOSE_STANDARD_SOCKET_APIS
/* Map standard socket API names to the TCPS equivalents. */
# define accept            Tcps_accept
# define addrinfo          Tcps_addrinfo
# define AI_PASSIVE        TCPS_AI_PASSIVE
# define AI_CANONNAME      TCPS_AI_CANONNAME
# define AI_NUMERICHOST    TCPS_AI_NUMERICHOST
# define AI_ALL            TCPS_AI_ALL
# define AI_ADDRCONFIG     TCPS_AI_ADDRCONFIG
# define AI_V4MAPPED       TCPS_AI_V4MAPPED
# define AF_INET           TCPS_AF_INET
# define AF_INET6          TCPS_AF_INET6
# define bind              Tcps_bind
# define connect           Tcps_connect
# define FD_ISSET(fd, set) Tcps_FDIsSet((TCPS_SOCKET)(fd), (Tcps_fd_set*)(set))
# define fd_set            Tcps_fd_set
# define FIONBIO           TCPS_FIONBIO
# define freeaddrinfo      Tcps_freeaddrinfo
# define getaddrinfo       Tcps_getaddrinfo
# define gethostname       Tcps_gethostname
# define getnameinfo       Tcps_getnameinfo
# define getpeername       Tcps_getpeername
# define getsockname       Tcps_getsockname
# define getsockopt        Tcps_getsockopt
# define htonl             Tcps_htonl
# define htons             Tcps_htons
# define in_addr           Tcps_in_addr
# define in6_addr          Tcps_in6_addr
# define inet_addr         Tcps_inet_addr
# define INVALID_SOCKET    TCPS_INVALID_SOCKET
# define IPV6_V6ONLY       TCPS_IPV6_V6ONLY
# define IPPROTO_IPV6      TCPS_IPPROTO_IPV6
# define IPPROTO_TCP       TCPS_IPPROTO_TCP
# define listen            Tcps_listen
# define MSG_WAITALL       TCPS_MSG_WAITALL
# define NI_NOFQDN         TCPS_NI_NOFQDN
# define NI_NUMERICHOST    TCPS_NI_NUMERICHOST
# define NI_NAMEREQD       TCPS_NI_NAMEREQD
# define NI_NUMERICSERV    TCPS_NI_NUMERICSERV
# define NI_DGRAM          TCPS_NI_DGRAM
# define NI_MAXHOST        TCPS_NI_MAXHOST
# define NI_MAXSERV        TCPS_NI_MAXSERV
# define ntohl             Tcps_ntohl
# define ntohs             Tcps_ntohs
# define recv              Tcps_recv
# define select            Tcps_select
# define send              Tcps_send
# define setsockopt        Tcps_setsockopt
# define shutdown          Tcps_shutdown
# define SOCK_STREAM       TCPS_SOCK_STREAM
# define sockaddr          Tcps_sockaddr
# define sockaddr_in       Tcps_sockaddr_in
# define sockaddr_in6      Tcps_sockaddr_in6
# define sockaddr_storage  Tcps_sockaddr_storage
# define socket            Tcps_socket
# define socklen_t         Tcps_socklen_t
# define SOCKET            TCPS_SOCKET
# define SOL_SOCKET        TCPS_SOL_SOCKET
# define SO_ERROR          TCPS_SO_ERROR
# define SO_KEEPALIVE      TCPS_SO_KEEPALIVE
# define SO_RCVBUF         TCPS_SO_RCVBUF
# define SO_SNDBUF         TCPS_SO_SNDBUF
# define SOMAXCONN         TCPS_SOMAXCONN
# define TCP_KEEPALIVE     TCPS_TCP_KEEPALIVE
# define TCP_NODELAY       TCPS_TCP_NODELAY
#endif

#ifndef NO_EXPOSE_WINSOCK_APIS
/* Map Winsock APIs to the TCPS equivalents. */
# define closesocket       Tcps_closesocket
# define ioctlsocket       Tcps_ioctlsocket
# define SOCKET_ERROR      TCPS_SOCKET_ERROR
# define WSADATA           TCPS_WSADATA
# define WSAECONNABORTED   TCPS_WSAECONNABORTED
# define WSAECONNRESET     TCPS_WSAECONNRESET
# define WSAEINPROGRESS    TCPS_WSAEINPROGRESS
# define WSAEWOULDBLOCK    TCPS_WSAEWOULDBLOCK
# define WSACleanup        Tcps_WSACleanup
# define WSAGetLastError   Tcps_WSAGetLastError
# define WSASetLastError   Tcps_WSASetLastError
# define WSAStartup        Tcps_WSAStartup
#endif

TCPS_SOCKET
Tcps_accept(
    _In_ TCPS_SOCKET s,
    _Out_writes_bytes_(*addrlen) struct Tcps_sockaddr* addr,
    _Inout_ int *addrlen);

int
Tcps_bind(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(namelen) const Tcps_sockaddr* name,
    _In_ int namelen);

int
Tcps_closesocket(
    _In_ TCPS_SOCKET s);

int
Tcps_connect(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(namelen) const Tcps_sockaddr* name,
    _In_ int namelen);

void
Tcps_freeaddrinfo(
    _In_ Tcps_addrinfo* ailist);

int
Tcps_getaddrinfo(
    _In_z_ const char* pNodeName,
    _In_z_ const char* pServiceName,
    _In_ const Tcps_addrinfo* pHints,
    _Out_ Tcps_addrinfo** ppResult);

int
Tcps_gethostname(
    _Out_writes_(len) char* name,
    _In_ size_t len);

int
Tcps_getnameinfo(
    _In_ const struct Tcps_sockaddr *sa,
    _In_ Tcps_socklen_t salen,
    _Out_writes_opt_z_(hostlen) char* host,
    _In_ size_t hostlen,
    _Out_writes_opt_z_(servlen) char* serv,
    _In_ size_t servlen,
    _In_ int flags);

int
Tcps_getpeername(
    _In_ TCPS_SOCKET s,
    _Out_writes_bytes_(*addrlen) struct Tcps_sockaddr* addr,
    _Inout_ int *addrlen);

int
Tcps_getsockname(
    _In_ TCPS_SOCKET s,
    _Out_writes_bytes_(*addrlen) struct Tcps_sockaddr* addr,
    _Inout_ int *addrlen);

int
Tcps_getsockopt(
    _In_ TCPS_SOCKET s,
    _In_ int level,
    _In_ int optname,
    _Out_writes_(*optlen) char* optval,
    _Inout_ int* optlen);

uint32_t
Tcps_htonl(
    _In_ uint32_t hostLong);

uint16_t
Tcps_htons(
    _In_ uint16_t hostShort);

uint32_t
Tcps_inet_addr(
    _In_z_ const char* cp);

int
Tcps_ioctlsocket(
    _In_ TCPS_SOCKET s,
    _In_ long cmd,
    _Inout_ u_long *argp);

int
Tcps_listen(
    _In_ TCPS_SOCKET s,
    _In_ int backlog);

uint32_t
Tcps_ntohl(
    _In_ uint32_t netLong);

uint16_t
Tcps_ntohs(
    _In_ uint16_t netShort);

int
Tcps_recv(
    _In_ TCPS_SOCKET s,
    _Out_writes_(len) char* buf,
    _In_ int len,
    _In_ int flags);

int
Tcps_select(
    _In_ int nfds,
    _Inout_opt_ Tcps_fd_set* readfds,
    _Inout_opt_ Tcps_fd_set* writefds,
    _Inout_opt_ Tcps_fd_set* exceptfds,
    _In_opt_ const struct timeval* timeout);

int
Tcps_send(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(len) const char* buf,
    _In_ int len,
    _In_ int flags);

int
Tcps_setsockopt(
    _In_ TCPS_SOCKET s,
    _In_ int level,
    _In_ int optname,
    _In_reads_bytes_(optlen) const char* optval,
    _In_ int optlen);

int
Tcps_shutdown(
    _In_ TCPS_SOCKET s,
    _In_ int how);

TCPS_SOCKET
Tcps_socket(
    _In_ Tcps_sa_family_t af,
    _In_ int type,
    _In_ int protocol);

typedef struct _TCPS_WSADATA {
    int unused;
} TCPS_WSADATA;

int Tcps_WSACleanup(void);

int Tcps_WSAGetLastError(void);

void Tcps_WSASetLastError(_In_ int iError);

int Tcps_WSAStartup(_In_ uint16_t wVersionRequired,
                    _Out_ TCPS_WSADATA* lpWSAData);

int
ServerConnectTransport(
    const char* HostName,
    unsigned short ServiceName,
    unsigned int Timeout,
    void** Context);

int
ClientConnectTransport(
    const char* HostName,
    unsigned short ServiceName,
    unsigned int Timeout,
    void** Context);

int
SendDataOverTransport(
    const uint8_t* Buffer,
    unsigned int Size,
    unsigned int Timeout,
    unsigned int* Sent,
    void* Context);

int
ReceiveDataOverTransport(
    uint8_t* Buffer,
    unsigned int Size,
    unsigned int Timeout,
    unsigned int* Recvd,
    void* Context);

void
ServerDisconnectTransport(
    void** Context);

void
ClientDisconnectTransport(
    void** Context);

#ifdef __cplusplus
}
#endif
