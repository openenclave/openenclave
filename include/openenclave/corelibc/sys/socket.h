// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_SOCKET_H
#define _OE_SYS_SOCKET_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/devids.h>
#include <openenclave/corelibc/sys/uio.h>

OE_EXTERNC_BEGIN

/* Protocol families.  */
#define OE_PF_UNSPEC 0      /* Unspecified.  */
#define OE_PF_LOCAL 1       /* Local to host (pipes and file-domain).  */
#define OE_PF_UNIX PF_LOCAL /* POSIX name for PF_LOCAL.  */
#define OE_PF_FILE PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define OE_PF_INET 2        /* IP protocol family.  */
#define OE_PF_AX25 3        /* Amateur Radio AX.25.  */
#define OE_PF_IPX 4         /* Novell Internet Protocol.  */
#define OE_PF_APPLETALK 5   /* Appletalk DDP.  */
#define OE_PF_NETROM 6      /* Amateur radio NetROM.  */
#define OE_PF_BRIDGE 7      /* Multiprotocol bridge.  */
#define OE_PF_ATMPVC 8      /* ATM PVCs.  */
#define OE_PF_X25 9         /* Reserved for X.25 project.  */
#define OE_PF_INET6 10      /* IP version 6.  */
#define OE_PF_ROSE 11       /* Amateur Radio X.25 PLP.  */
#define OE_PF_DECnet 12     /* Reserved for DECnet project.  */
#define OE_PF_NETBEUI 13    /* Reserved for 802.2LLC project.  */
#define OE_PF_SECURITY 14   /* Security callback pseudo AF.  */
#define OE_PF_KEY 15        /* PF_KEY key management API.  */
#define OE_PF_NETLINK 16
#define OE_PF_ROUTE PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define OE_PF_PACKET 17        /* Packet family.  */
#define OE_PF_ASH 18           /* Ash.  */
#define OE_PF_ECONET 19        /* Acorn Econet.  */
#define OE_PF_ATMSVC 20        /* ATM SVCs.  */
#define OE_PF_RDS 21           /* RDS sockets.  */
#define OE_PF_SNA 22           /* Linux SNA Project */
#define OE_PF_IRDA 23          /* IRDA sockets.  */
#define OE_PF_PPPOX 24         /* PPPoX sockets.  */
#define OE_PF_WANPIPE 25       /* Wanpipe API sockets.  */
#define OE_PF_LLC 26           /* Linux LLC.  */
#define OE_PF_IB 27            /* Native InfiniBand address.  */
#define OE_PF_MPLS 28          /* MPLS.  */
#define OE_PF_CAN 29           /* Controller Area Network.  */
#define OE_PF_TIPC 30          /* TIPC sockets.  */
#define OE_PF_BLUETOOTH 31     /* Bluetooth sockets.  */
#define OE_PF_IUCV 32          /* IUCV sockets.  */
#define OE_PF_RXRPC 33         /* RxRPC sockets.  */
#define OE_PF_ISDN 34          /* mISDN sockets.  */
#define OE_PF_PHONET 35        /* Phonet sockets.  */
#define OE_PF_IEEE802154 36    /* IEEE 802.15.4 sockets.  */
#define OE_PF_CAIF 37          /* CAIF sockets.  */
#define OE_PF_ALG 38           /* Algorithm sockets.  */
#define OE_PF_NFC 39           /* NFC sockets.  */
#define OE_PF_VSOCK 40         /* vSockets.  */
#define OE_PF_KCM 41           /* Kernel Connection Multiplexor.  */
#define OE_PF_QIPCRTR 42       /* Qualcomm IPC Router.  */
#define OE_PF_SMC 43           /* SMC sockets.  */
#define OE_PF_ENCLAVE 50       /* secure sockets */
#define OE_PF_HOST 51          /* non-secure host sockets */
#define OE_PF_MAX 51           /* For now..  */

/* Address families.  */
#define OE_AF_UNSPEC OE_PF_UNSPEC
#define OE_AF_LOCAL OE_PF_LOCAL
#define OE_AF_UNIX OE_PF_UNIX
#define OE_AF_FILE OE_PF_FILE
#define OE_AF_INET OE_PF_INET
#define OE_AF_AX25 OE_PF_AX25
#define OE_AF_IPX OE_PF_IPX
#define OE_AF_APPLETALK OE_PF_APPLETALK
#define OE_AF_NETROM OE_PF_NETROM
#define OE_AF_BRIDGE OE_PF_BRIDGE
#define OE_AF_ATMPVC OE_PF_ATMPVC
#define OE_AF_X25 OE_PF_X25
#define OE_AF_INET6 OE_PF_INET6
#define OE_AF_ROSE OE_PF_ROSE
#define OE_AF_DECnet OE_PF_DECnet
#define OE_AF_NETBEUI OE_PF_NETBEUI
#define OE_AF_SECURITY OE_PF_SECURITY
#define OE_AF_KEY OE_PF_KEY
#define OE_AF_NETLINK OE_PF_NETLINK
#define OE_AF_ROUTE OE_PF_ROUTE
#define OE_AF_PACKET OE_PF_PACKET
#define OE_AF_ASH OE_PF_ASH
#define OE_AF_ECONET OE_PF_ECONET
#define OE_AF_ATMSVC OE_PF_ATMSVC
#define OE_AF_RDS OE_PF_RDS
#define OE_AF_SNA OE_PF_SNA
#define OE_AF_IRDA OE_PF_IRDA
#define OE_AF_PPPOX OE_PF_PPPOX
#define OE_AF_WANPIPE OE_PF_WANPIPE
#define OE_AF_LLC OE_PF_LLC
#define OE_AF_IB OE_PF_IB
#define OE_AF_MPLS OE_PF_MPLS
#define OE_AF_CAN OE_PF_CAN
#define OE_AF_TIPC OE_PF_TIPC
#define OE_AF_BLUETOOTH OE_PF_BLUETOOTH
#define OE_AF_IUCV OE_PF_IUCV
#define OE_AF_RXRPC OE_PF_RXRPC
#define OE_AF_ISDN OE_PF_ISDN
#define OE_AF_PHONET OE_PF_PHONET
#define OE_AF_IEEE802154 OE_PF_IEEE802154
#define OE_AF_CAIF OE_PF_CAIF
#define OE_AF_ALG OE_PF_ALG
#define OE_AF_NFC OE_PF_NFC
#define OE_AF_VSOCK OE_PF_VSOCK
#define OE_AF_KCM OE_PF_KCM
#define OE_AF_QIPCRTR OE_PF_QIPCRTR
#define OE_AF_SMC OE_PF_SMC
#define OE_AF_ENCLAVE OE_PF_ENCLAVE
#define OE_AF_HOST OE_PF_HOST
#define OE_AF_MAX OE_PF_MAX

/* oe_setsockopt()/oe_getsockopt() options. */
#define OE_SOL_SOCKET 1
#define OE_SO_DEBUG 1
#define OE_SO_REUSEADDR 2
#define OE_SO_TYPE 3
#define OE_SO_ERROR 4
#define OE_SO_DONTROUTE 5
#define OE_SO_BROADCAST 6
#define OE_SO_SNDBUF 7
#define OE_SO_RCVBUF 8
#define OE_SO_SNDBUFFORCE 32
#define OE_SO_RCVBUFFORCE 33
#define OE_SO_KEEPALIVE 9
#define OE_SO_OOBINLINE 10
#define OE_SO_NO_CHECK 11
#define OE_SO_PRIORITY 12
#define OE_SO_LINGER 13
#define OE_SO_BSDCOMPAT 14
#define OE_SO_REUSEPORT 15

/* oe_shutdown() options. */
#define OE_SHUT_RD 0
#define OE_SHUT_WR 1
#define OE_SHUT_RDWR 2

struct oe_sockaddr
{
#include <openenclave/corelibc/sys/bits/sockaddr.h>
};

struct oe_sockaddr_storage
{
#include <openenclave/corelibc/sys/bits/sockaddr_storage.h>
};

struct oe_msghdr
{
    void* msg_name;        /* Address to send to/receive from.  */
    socklen_t msg_namelen; /* Length of address data.  */

    struct oe_iovec* msg_iov; /* Vector of data to send/receive into.  */
    size_t msg_iovlen;        /* Number of elements in the vector.  */

    void* msg_control;     /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen; /* Ancillary data buffer length.
                              !! The type should be socklen_t but the
                              definition of the linux kernel is incompatible
                              with this.  */

    int msg_flags; /* Flags on received message.  */
};

void oe_set_default_socket_devid(uint64_t devid);

uint64_t oe_get_default_socket_devid(void);

int oe_socket(int domain, int type, int protocol);

int oe_socketpair(int domain, int type, int protocol, int rtnfd[2]);

int oe_accept(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen);

int oe_bind(int sockfd, const struct oe_sockaddr* addr, socklen_t namelen);

int oe_connect(int sockfd, const struct oe_sockaddr* addr, socklen_t namelen);

int oe_shutdown(int sockfd, int how);

int oe_listen(int sockfd, int backlog);

int oe_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen);

int oe_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen);

ssize_t oe_send(int sockfd, const void* buf, size_t len, int flags);
ssize_t oe_sendmsg(int sockfd, const struct oe_msghdr* buf, int flags);

ssize_t oe_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t oe_recvmsg(int sockfd, struct oe_msghdr* buf, int flags);

int oe_socket_d(uint64_t devid, int domain, int type, int protocol);

int oe_getpeername(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen);

int oe_getsockname(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen);

#if defined(OE_NEED_STDC_NAMES)

#define PF_UNSPEC OE_PF_UNSPEC
#define PF_LOCAL OE_PF_LOCAL
#define PF_UNIX OE_PF_UNIX
#define PF_FILE OE_PF_FILE
#define PF_INET OE_PF_INET
#define PF_AX25 OE_PF_AX25
#define PF_IPX OE_PF_IPX
#define PF_APPLETALK OE_PF_APPLETALK
#define PF_NETROM OE_PF_NETROM
#define PF_BRIDGE OE_PF_BRIDGE
#define PF_ATMPVC OE_PF_ATMPVC
#define PF_X25 OE_PF_X25
#define PF_INET6 OE_PF_INET6
#define PF_ROSE OE_PF_ROSE
#define PF_DECnet OE_PF_DECnet
#define PF_NETBEUI OE_PF_NETBEUI
#define PF_SECURITY OE_PF_SECURITY
#define PF_KEY OE_PF_KEY
#define PF_NETLINK OE_PF_NETLINK
#define PF_ROUTE OE_PF_ROUTE
#define PF_PACKET OE_PF_PACKET
#define PF_ASH OE_PF_ASH
#define PF_ECONET OE_PF_ECONET
#define PF_ATMSVC OE_PF_ATMSVC
#define PF_RDS OE_PF_RDS
#define PF_SNA OE_PF_SNA
#define PF_IRDA OE_PF_IRDA
#define PF_PPPOX OE_PF_PPPOX
#define PF_WANPIPE OE_PF_WANPIPE
#define PF_LLC OE_PF_LLC
#define PF_IB OE_PF_IB
#define PF_MPLS OE_PF_MPLS
#define PF_CAN OE_PF_CAN
#define PF_TIPC OE_PF_TIPC
#define PF_BLUETOOTH OE_PF_BLUETOOTH
#define PF_IUCV OE_PF_IUCV
#define PF_RXRPC OE_PF_RXRPC
#define PF_ISDN OE_PF_ISDN
#define PF_PHONET OE_PF_PHONET
#define PF_IEEE802154 OE_PF_IEEE802154
#define PF_CAIF OE_PF_CAIF
#define PF_ALG OE_PF_ALG
#define PF_NFC OE_PF_NFC
#define PF_VSOCK OE_PF_VSOCK
#define PF_KCM OE_PF_KCM
#define PF_QIPCRTR OE_PF_QIPCRTR
#define PF_SMC OE_PF_SMC
#define PF_MAX OE_PF_MAX
#define AF_UNSPEC OE_AF_UNSPEC
#define AF_LOCAL OE_AF_LOCAL
#define AF_UNIX OE_AF_UNIX
#define AF_FILE OE_AF_FILE
#define AF_INET OE_AF_INET
#define AF_AX25 OE_AF_AX25
#define AF_IPX OE_AF_IPX
#define AF_APPLETALK OE_AF_APPLETALK
#define AF_NETROM OE_AF_NETROM
#define AF_BRIDGE OE_AF_BRIDGE
#define AF_ATMPVC OE_AF_ATMPVC
#define AF_X25 OE_AF_X25
#define AF_INET6 OE_AF_INET6
#define AF_ROSE OE_AF_ROSE
#define AF_DECnet OE_AF_DECnet
#define AF_NETBEUI OE_AF_NETBEUI
#define AF_SECURITY OE_AF_SECURITY
#define AF_KEY OE_AF_KEY
#define AF_NETLINK OE_AF_NETLINK
#define AF_ROUTE OE_AF_ROUTE
#define AF_PACKET OE_AF_PACKET
#define AF_ASH OE_AF_ASH
#define AF_ECONET OE_AF_ECONET
#define AF_ATMSVC OE_AF_ATMSVC
#define AF_RDS OE_AF_RDS
#define AF_SNA OE_AF_SNA
#define AF_IRDA OE_AF_IRDA
#define AF_PPPOX OE_AF_PPPOX
#define AF_WANPIPE OE_AF_WANPIPE
#define AF_LLC OE_AF_LLC
#define AF_IB OE_AF_IB
#define AF_MPLS OE_AF_MPLS
#define AF_CAN OE_AF_CAN
#define AF_TIPC OE_AF_TIPC
#define AF_BLUETOOTH OE_AF_BLUETOOTH
#define AF_IUCV OE_AF_IUCV
#define AF_RXRPC OE_AF_RXRPC
#define AF_ISDN OE_AF_ISDN
#define AF_PHONET OE_AF_PHONET
#define AF_IEEE802154 OE_AF_IEEE802154
#define AF_CAIF OE_AF_CAIF
#define AF_ALG OE_AF_ALG
#define AF_NFC OE_AF_NFC
#define AF_VSOCK OE_AF_VSOCK
#define AF_KCM OE_AF_KCM
#define AF_QIPCRTR OE_AF_QIPCRTR
#define AF_SMC OE_AF_SMC
#define AF_MAX OE_AF_MAX
#define SOL_SOCKET OE_SOL_SOCKET
#define SO_DEBUG OE_SO_DEBUG
#define SO_REUSEADDR OE_SO_REUSEADDR
#define SO_TYPE OE_SO_TYPE
#define SO_ERROR OE_SO_ERROR
#define SO_DONTROUTE OE_SO_DONTROUTE
#define SO_BROADCAST OE_SO_BROADCAST
#define SO_SNDBUF OE_SO_SNDBUF
#define SO_RCVBUF OE_SO_RCVBUF
#define SO_SNDBUFFORCE OE_SO_SNDBUFFORCE
#define SO_RCVBUFFORCE OE_SO_RCVBUFFORCE
#define SO_KEEPALIVE OE_SO_KEEPALIVE
#define SO_OOBINLINE OE_SO_OOBINLINE
#define SO_NO_CHECK OE_SO_NO_CHECK
#define SO_PRIORITY OE_SO_PRIORITY
#define SO_LINGER OE_SO_LINGER
#define SO_BSDCOMPAT OE_SO_BSDCOMPAT
#define SO_REUSEPORT OE_SO_REUSEPORT
#define SHUT_RD OE_SHUT_RD
#define SHUT_WR OE_SHUT_WR
#define SHUT_RDWR OE_SHUT_RDWR

struct sockaddr
{
#include <openenclave/corelibc/sys/bits/sockaddr.h>
};

struct sockaddr_storage
{
#include <openenclave/corelibc/sys/bits/sockaddr_storage.h>
};

OE_INLINE int socket(int domain, int type, int protocol)
{
    return oe_socket(domain, type, protocol);
}

OE_INLINE int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    return oe_accept(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_INLINE int bind(int sockfd, const struct sockaddr* addr, socklen_t namelen)
{
    return oe_bind(sockfd, (struct oe_sockaddr*)addr, namelen);
}

OE_INLINE int connect(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t namelen)
{
    return oe_connect(sockfd, (struct oe_sockaddr*)addr, namelen);
}

OE_INLINE int shutdown(int sockfd, int how)
{
    return oe_shutdown(sockfd, how);
}

OE_INLINE int listen(int sockfd, int backlog)
{
    return oe_listen(sockfd, backlog);
}

OE_INLINE int setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    return oe_setsockopt(sockfd, level, optname, optval, optlen);
}

OE_INLINE int getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    return oe_getsockopt(sockfd, level, optname, optval, optlen);
}

OE_INLINE ssize_t send(int sockfd, const void* buf, size_t len, int flags)
{
    return oe_send(sockfd, buf, len, flags);
}

OE_INLINE ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
    return oe_recv(sockfd, buf, len, flags);
}

OE_INLINE int getpeername(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    return oe_getpeername(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_INLINE int getsockname(
    int sockfd,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    return oe_getsockname(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_SOCKET_H */
