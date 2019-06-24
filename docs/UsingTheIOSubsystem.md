Using the Open Enclave I/O subsystem
====================================

Introduction
============

This document explains how to use the **Open Enclave I/O subsystem**, which
encompasses file I/O and socket I/O. This subsystem provides enclaves with
access to files and sockets. In particular, the following features are
supported.

- **POSIX file I/O** (e.g., open, read, etc.)
- **Buffered file I/O** (e.g., fopen, fread, etc.)
- **File control** (e.g., fcntl, ioctl, etc.)
- **File manipulation** (e.g., link, remove, rename, etc.)
- **File information** (e.g., stat, access, etc.)
- **File system mounting** (e.g., mount, umount, umount2)
- **Directory enumeration** (e.g., opendir, readdir, etc.)
- **Directory manipulation** (e.g., mkdir, rmdir, chdir, getcwd, etc.)
- **Sockets** (e.g., socket, listen, bind, accept, send, recv, etc.)
- **Polling** (e.g., select, poll)
- **System information** (e.g., gethostname, getdomainname)
- **Network information** (e.g., getaddrinfo, getnameinfo)
- **Process/user/group information** (e.g., getpid, getuid, getgid, etc.)

Chapter 1 provides an overview of the subsystem. Chapter 2 discusses which
system functions are supported.

Chapter 1: Overview
===================

The **Open Enclave I/O subsystem** exposes I/O features through ordinary system
header files. These headers fall roughly into three categories.

- **C headers** (such as stdio.h, stdlib.h)
- **POSIX headers** (such as socket.h, dirent.h, fnctl.h, stat.h)
- **Linux headers** (such as mount.h)

**Open Enclave** provides a partial implementation of these headers and many
others. These headers are part of [**musl libc**](https://www.musl-libc.org),
which **Open Enclave** redistributes for use within enclaves under the name
**oelibc**. The I/O subsystem expands **oelibc** to support many additional
functions.

For the most part, developers just use standard headers to build enclaves;
however, a few additional functions are needed to select which I/O features
are needed. This is purely a security measure. By default, enclaves have no
access to files or sockets. The next section describes how to opt-in to
various I/O features.

Opting in
---------

An enclave application must first opt in to the I/O features it wishes to
use. Opting in is a matter of (1) linking the desired module libraries and
(2) calling functions to load the modules. I/O features are packaged as
static libraries. This release provides the following modules.

- **liboehostfs** -- access to non-secure host files and directories.
- **liboehostsock** -- access to non-secure sockets.
- **libhostresolver** -- access to network information.

After linking modules, the enclave loads modules by calling one of the
following.

- **oe_load_module_host_file_system()**
- **oe_load_module_host_socket_interface()**
- **oe_load_module_host_resolver()**

Operating system support
------------------------

The current version is Limited to Linux hosts but Windows host is under
development now.

File system path resolution
---------------------------

Path-oriented functions must resolve their path parameter to a file system
device. There are two mechanisms for doing this. The first mechanisms employs
the Linux **mount** function defined below.

```
#include <sys/mount.h>

int mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data);
```

This function attaches a file system to the directory specifies by **target**.
**filesystemtype** parameter specifies the name of the file system. The next
section will show how to mount the non-secure host file system.

The second path-resolution mechanism employs the following functions.

```
oe_result_t oe_set_thread_devid(uint64_t devid);
oe_result_t oe_clear_thread_devid();
```

The **oe_set_thread_devid** function sets the device id for the current
thread. Once set, that device is used by path-oriented functions until
it is cleared by calling **oe_clear_thread_devid**. These functions can be
used to wrap calls to path-oriented functions. Consider the following function
definition.

```
#include <stdio.h>
#include <openenclave/enclave.h>

FILE* fopen_by_device(uint64_t devid, const char *path, const char *mode)
{
    extern oe_result_t oe_set_thread_devid(uint64_t devid);
    extern oe_result_t oe_clear_thread_devid(uint64_t devid);

    oe_set_thread_devid(devid);
    FILE* stream = fopen(path, mode);
    oe_clear_thread_devid(devid);

    return stream;
}
```

This function can then be used to compose device-specific functions. For
example.

```
FILE* fopen_host_file_system(const char *path, const char *mode)
{
    const uint64_t OE_DEVID_HOST_FILE_SYSTEM = 1;

    return fopen_by_device(OE_DEVID_HOST_FILE_SYSTEM, path, mode);
}
```

Caution: the thread-devid functions are experimental in the current release.

A file system example
----------------------

This section shows how an enclave may create a file on the host file system.
First the enclave links **liboehostfs** and then loads the **host file system**
module and mounts this file system as shown below.

```
#include <openenclave/enclave.h>
#include <sys/mount.h>

int setup()
{
    oe_result_t result;

    /* Load the host file system module. */
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
        return -1;

    /* Mount the host file system on the root directory. */
    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
        return -1;

    return 0;
}
```

The **mount()** function is discussed later in this document.

The following function makes use of the standard C stream functions to create
a new file that contains the letters of the alphabet.

```
#include <stdio.h>
#include <string.h>

int create_alphabet_file(const char* path)
{
    FILE* stream = NULL;
    const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz";

    /* Open the file for write. */
    if (!(stream = fopen(path, "w")))
        return -1;

    /* Write the letters of the alphabet to the file. */
    if (fwrite(alphabet, 1, sizeof(alphabet), stream) != sizeof(ALPHABET))
    {
        fclose(stream);
        return -1;
    }

    fclose(stream);

    return 0;
}
```

A socket example
----------------

This section provides an example of an enclave that runs an echo service. This
service accepts a client connection, reads a request, writes the request back
to the client, and closes the connection. Before the service can run, the
appropriate module is loaded as shown below. Also this enclave application
must be linked with **liboehostsock**.

```
#include <openenclave/enclave.h>

void setup()
{
    oe_load_module_host_socket_interface();
}
```

The function that runs the services is listed below.

```
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void echod_server(uint16_t port)
{
    int listener;

    /* Create the listener socket. */
    if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        error_exit("socket() failed: errno=%d", errno);

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, opt_len) != 0)
            error_exit("setsockopt() failed: errno=%d", errno);
    }

    /* Listen on this address. */
    {
        struct sockaddr_in addr;
        const int backlog = 10;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0)
            error_exit("bind() failed: errno=%d", errno);

        if (listen(listener, backlog) != 0)
            error_exit("listen() failed: errno=%d", errno);
    }

    /* Accept-recv-send-close until a zero value is received. */
    for (;;)
    {
        int client;
        uint64_t value;

        if ((client = accept(listener, NULL, NULL)) < 0)
            error_exit("accept() failed: errno=%d", errno);

        if (recv_n(client, &value, sizeof(value)) != 0)
            error_exit("recv_n() failed: errno=%d", errno);

        if (send_n(client, &value, sizeof(value)) != 0)
            error_exit("send_n() failed: errno=%d", errno);

        close(client);

        if (value == 0)
            break;
    }

    close(listener);
}
```

The client listing follows.

```
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void echod_client(uint16_t port, uint64_t value)
{
    int sock;

    /* Create the client socket. */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        error_exit("socket() failed: errno=%d", errno);

    /* Connect to the server. */
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
            error_exit("connectd() failed: errno=%d", errno);
    }

    /* write/read "hello" to/from  the server. */
    {
        uint64_t tmp;

        if (send_n(sock, &value, sizeof(value)) != 0)
            error_exit("send_n() failed: errno=%d", errno);

        if (recv_n(sock, &tmp, sizeof(tmp)) != 0)
            error_exit("recv_n() failed: errno=%d", errno);

        if (tmp != value)
            error_exit("comparison failed");
    }

    close(sock);
}
```

Chapter 1: Supported functions
==============================

This chapter discusses which system functions are supported by the I/O
subsystem. Each section discusses a system header file, describing which
functions are supported.

**<stdio.h>**
-------------

For the **<stdio.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| clearerr          |                                                          |
| dprintf           |                                                          |
| fclose            |                                                          |
| fdopen            |                                                          |
| feof              |                                                          |
| ferror            |                                                          |
| fflush            |                                                          |
| fgetc             |                                                          |
| fgetln            |                                                          |
| fgetpos           |                                                          |
| fgets             |                                                          |
| fileno            |                                                          |
| fopen             |                                                          |
| fprintf           |                                                          |
| fputs             |                                                          |
| fread             |                                                          |
| freopen           |                                                          |
| fscanf            |                                                          |
| fseeko            |                                                          |
| fseek             |                                                          |
| fsetpos           |                                                          |
| ftello            |                                                          |
| ftell             |                                                          |
| fwrite            |                                                          |
| getc              |                                                          |
| gets              |                                                          |
| remove            |                                                          |
| rename            |                                                          |
| rewind            |                                                          |
| setbuffer         |                                                          |
| setbuf            |                                                          |
| setlinebuf        |                                                          |
| setvbuf           |                                                          |
| vdprintf          |                                                          |
| vfprintf          |                                                          |
| vfscanf           |                                                          |
|                   | <img width="1000">                                       |

**<stdlib.h>**
-------------

For the **<stdlib.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| realpath          | Canonicalizes path but does not resolve symbolic links.  |
|                   | <img width="1000">                                       |

**<fcntl.h>**
-------------

For the **<fcntl.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| fcntl             | Only partial support for command types.                  |
| open              |                                                          |
|                   | <img width="1000">                                       |

**<unistd.h>**
-------------

For the **<unistd.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| access            |                                                          |
| chdir             |                                                          |
| close             |                                                          |
| dup               |                                                          |
| dup2              |                                                          |
| getcwd            |                                                          |
| getdomainname     |                                                          |
| getegid           |                                                          |
| geteuid           |                                                          |
| getgid            |                                                          |
| getgroups         |                                                          |
| gethostname       |                                                          |
| getpgid           |                                                          |
| getpgrp           |                                                          |
| getpid            |                                                          |
| getppid           |                                                          |
| getuid            |                                                          |
| link              |                                                          |
| lseek             |                                                          |
| read              |                                                          |
| rmdir             |                                                          |
| sleep             |                                                          |
| unlink            |                                                          |
| write             |                                                          |
|                   | <img width="1000">                                       |

**<netdb.h>**
-------------

For the **<netdb.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| freeaddrinfo      |                                                          |
| getaddrinfo       |                                                          |
| getnameinfo       |                                                          |
|                   | <img width="1000">                                       |

**<socket.h>**
-------------

For the **<socket.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| accept            |                                                          |
| bind              |                                                          |
| connect           |                                                          |
| getpeername       |                                                          |
| getsockname       |                                                          |
| getsockopt        |                                                          |
| listen            |                                                          |
| recv              |                                                          |
| recvfrom          |                                                          |
| recvmsg           |                                                          |
| send              |                                                          |
| sendmsg           |                                                          |
| sendto            |                                                          |
| setsockopt        |                                                          |
| shutdown          |                                                          |
| socket            |                                                          |
| socketpair        |                                                          |
|                   | <img width="1000">                                       |

**<select.h>**
-------------

For the **<select.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| FD_CLR            |                                                          |
| FD_ISSET          |                                                          |
| FD_SET            |                                                          |
| FD_ZERO           |                                                          |
| select            |                                                          |
|                   | <img width="1000">                                       |

**<dirent.h>**
-------------

For the **<dirent.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| closedir          |                                                          |
| opendir           |                                                          |
| readdir           |                                                          |
| readdir_r         |                                                          |
| rewinddir         |                                                          |
| telldir           |                                                          |
|                   | <img width="1000">                                       |

**<poll.h>**
-------------

For the **<poll.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| poll              |                                                          |
|                   | <img width="1000">                                       |

**<poll.h>**
-------------

For the **<poll.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| poll              |                                                          |
|                   | <img width="1000">                                       |

**<ioctl.h>**
-------------

For the **<ioctl.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| ioctl             | Only partial support for request types.                  |
|                   | <img width="1000">                                       |

**<mount.h>**
-------------

For the **<mount.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| mount             |                                                          |
| umount            |                                                          |
| umount2           |                                                          |
|                   | <img width="1000">                                       |

**<uname.h>**
-------------

For the **<uname.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| uname             |                                                          |
|                   | <img width="1000">                                       |


**<sys/uio.h>**
-------------

For the **<sys/uio.h>** header, the I/O subsystem adds support for the following
functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| readv             |                                                          |
| writev            |                                                          |
|                   | <img width="1000">                                       |

**<sys/stat.h>**
-------------

For the **<sys/stat.h>** header, the I/O subsystem adds support for the
following functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| mkdir             |                                                          |
| stat              |                                                          |
|                   | <img width="1000">                                       |

**<arpa/inet.h>**
-------------

For the **<arpa/inet.h>** header, the I/O subsystem adds support for the
following functions.

| Function          | Limitations                                              |
| :---              | :---                                                     |
| htonl             |                                                          |
| htons             |                                                          |
| ntohl             |                                                          |
| ntohs             |                                                          |
| inet_addr         |                                                          |
|                   | <img width="1000">                                       |
