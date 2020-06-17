// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_SOCKET_H
#define _OE_SYSCALL_SYS_SOCKET_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/internal/bits/socket.h>
#include <openenclave/internal/syscall/sys/uio.h>

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

#define OE_MSG_PEEK 0x0002

#define __OE_SOCKADDR_STORAGE oe_sockaddr_storage
#include <openenclave/internal/syscall/sys/bits/sockaddr_storage.h>
#undef __OE_SOCKADDR_STORAGE

#define __OE_IOVEC oe_iovec
#define __OE_MSGHDR oe_msghdr
#include <openenclave/internal/syscall/sys/bits/msghdr.h>
#undef __OE_IOVEC
#undef __OE_MSGHDR

void oe_set_default_socket_devid(uint64_t devid);

uint64_t oe_get_default_socket_devid(void);

int oe_socket(int domain, int type, int protocol);

int oe_socket_d(uint64_t devid, int domain, int type, int protocol);

int oe_socketpair(int domain, int type, int protocol, int rtnfd[2]);

int oe_accept(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen);

int oe_bind(int sockfd, const struct oe_sockaddr* addr, oe_socklen_t namelen);

int oe_connect(
    int sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t namelen);

int oe_shutdown(int sockfd, int how);

int oe_listen(int sockfd, int backlog);

int oe_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen);

int oe_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t* optlen);

ssize_t oe_send(int sockfd, const void* buf, size_t len, int flags);

ssize_t oe_recv(int sockfd, void* buf, size_t len, int flags);

ssize_t oe_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen);

ssize_t oe_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t* addrlen);

ssize_t oe_sendmsg(int sockfd, const struct oe_msghdr* buf, int flags);

ssize_t oe_recvmsg(int sockfd, struct oe_msghdr* buf, int flags);

int oe_getpeername(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen);

int oe_getsockname(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_SOCKET_H */
