The Open Enclave I/O system
===========================

1 Overview
==========

This document describes the **Open Enclave** I/O system, which provides a
framework for building devices and a set of predefined devices. OE supports
two types of devices.

- File-system devices
- Socket devices

Examples of **file-system devices** include:

- The non-secure **host file system** device (hostfs).
- The Intel **protected file system** device (sgxfs).
- The ARM **secure hardware file system** device (shwfs).
- The **Open Enclave File System** device (oefs).

Examples of the **socket devices** include:

- The non-secure **host sockets** device.
- The secure **enclave sockets** device.
- The OPTEE **secure-sockets** device.

Open Enclave provides three programming interfaces to meet the needs of
different applications.

- The device-oriented interface, which addresses devices by id rather than by
    path (for files) or domain (for sockets). Examples include:
    - int oe_device_open(int devid, const char* path, int flags, mode_t mode);
    - int oe_device_rmdir(int devid, const char* pathname);
    - int oe_device_socket(int devid, int domain, int type, int protocol);
- The POSIX interface, which includes:
    - Stream-based file I/O (**fopen()**, **fwrite()**, etc.).
    - Low-level file I/O (**open()**, **write()**).
    - POSIX/BSD socket I/O (**socket()**, **recv()**).
- The IOT interface, which includes customized, macro-driven headers, including:
    - **<stdio.h>**
    - **<socket.h>**

Each of these interfaces builds on the one above it in the list. The next
section discusses these in detail.

2 Interfaces
============

This section describes the three interfaces introduced in the previous section.

2.1 The device-oriented interface
---------------------------------

The device-oriented interface addresses devices by a **device id** rather than
by path (for files) or domain (for sockets). This interface defines functions
similar to their POSIX counterparts, except for the use of of an extra
**devid** parameter. For example, consider the POSIX **open()** function.

```
int open(const char *pathname, int flags, mode_t mode);
```

The device-oriented form of this method is defined as follows.

```
int oe_device_open(int devid, const char *pathname, int flags, mode_t mode);
```

The **devid** parameter is the integer ID of the device that will perform
the operation. **Open Enclave** shall support the following device ids.

- **OE_DEVID_HOST_FILE_SYSTEM** (non-secure host file system).
- **OE_DEVID_PROTECTED_FILE_SYSTEM** (Intel's protected file system).
- **OE_DEVID_SECURE_HARDWARE_FILE_SYSTEM** (OPTEE secure hardware file system).
- **OE_DEVID_OPEN_ENCLAVE_FILE_SYSTEM** (Open enclave whole disk file system).
- **OE_DEVID_HOST_SOCKETS** (non-secure host sockets).
- **OE_DEVID_ENCLAVE_SOCKETS** (secure enclave-to-enclave sockets).
- **OE_DEVID_SECURE_SOCKETS** (OPTEE secure sockets).

The following example uses the device interface to create an unencrypted file
on the host file system.

```
    int fd;
    const int flags = OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY;
    const oe_mode_t mode = 0644;

    fd = oe_device_open(OE_DEVID_HOST_FILE_SYSTEM, "/tmp/hello", flags, mode);
    ...
    oe_write(fd, "hello", 5);
    ...
    oe_close(fd);
```

The oe-prefixed functions that have POSIX signatures (**oe_write()**,
**oe_close**(), etc.) allow enclaves to perform I/O without a C runtime.
The following section discusses the corresponding POSIX functions defined
by the C runtime.

Similarly, the following shows how to create a non-secure socket using the
device-oriented interface.

```
    int sd;
    const int domain = OE_AF_INET6;
    const int type = OE_SOCK_STREAM;
    const int protocol = 0;

    sd = oe_device_socket(OE_DEVID_HOST_SOCKETS, domain, type, protocol);
    ...
    oe_write(sd, "hello", 5);
    ...
    oe_close(sd);
```

The device in this example is determined by the domain (address family)
parameter, which is OE_AF_INET6 in this case. Passing OE_AF_ENCLAVE, creates
a secure enclave socket.

The device interface also provides functions for opening stream-oriented
files. For example:

```
    OE_FILE* stream;

    stream = oe_device_fopen(OE_DEVID_HOST_FILE_SYSTEM, "/tmp/hello", "r");
    fwrite("hello", 1, 5, stream);
    fclose(stream);
```

The **fwrite** and **fclose** functions are part of the POSIX interface,
discussed in the next chapter.

The following is a complete list of functions defined by the device-oriented
interface


| The device-oriented interface |
| ----------------------------- |
| oe_device_access()            |
| oe_device_fopen()             |
| oe_device_link()              |
| oe_device_mkdir()             |
| oe_device_open()              |
| oe_device_opendir()           |
| oe_device_rename()            |
| oe_device_rmdir()             |
| oe_device_stat()              |
| oe_device_truncate()          |
| oe_device_unlink()            |

2.2 The POSIX interface
-----------------------

This section discusses the POSIX compatibility interface. Open Enclave provides
many POSIX to ease porting of legacy applications.

### 2.2.1 Overview

The POSIX interface supports the following groups of functions.

- The stream-oriented file I/O functions (**fopen()**, **fwrite**(), etc.).
- The fd-oriented file I/O functions (**open()**, **write**(), etc.).
- The path-oriented file I/O functions (**mkdir()**, **stat**(), etc.).
- The directory-scanning functions (**opendir()**, **readdir**(), etc.).
- The socket functions (**socket()**, **connect()**, **send()**, etc.);

The target audience for this interface are those who want to build (or just
re-link) their applications without any code changes.

The POSIX functions are path-oriented, so Open Enclave provides a mechanism
for associating devices with mount points. For this, Open Enclave supports
the following functions.

```
int oe_mount(int devid, const char* source, const char* target, uint32_t flags);
int oe_unmount(int devid, const char* target);
```

The following example mounts the **Intel Protected File System** and uses it
to write a file.

```
    FILE* stream;

    oe_mount(OE_DEVICE_ID_INSECURE_FS, NULL, "/insecure", 0);
    oe_mount(OE_DEVID_PROTECTED_FILE_SYSTEM, NULL, "/secure", 0);

    stream = fopen("/secure/file1", "r");
    fwrite("hello", 1, 5, stream);
    fclose(stream);

    stream = fopen("/insecure/file2", "r");
    fwrite("hello", 1, 5, stream);
    fclose(stream);
```

Once mounted, files associated with that device may be manipulated by any of
the POSIX path-addressed functions (whether stream-oriented and fd-oriented).

Socket I/O can be performed with the usual POSIX calls.

```
    int sd;

    sd = socket(AF_INET6, SOCK_STREAM, 0);
    ...
    connect(sd, &addr, sizeof(addr));
    ...
    write(sd, "hello", 5);
    ...
    close(sd);
```

### 2.2.2 The stream-oriented file I/O functions

Open Enclave provides full support for stream-oriented functions. For example:

```
    FILE* stream;

    stream = fopen("/sgxfs/hello", "r");
    fwrite("hello", 1, 5, stream);
    fclose(stream);
```

Open Enclave does not implement the stream-oriented functions directly. Instead
it uses the implementation from the C runtime (MUSL). Since C runtimes use the
fd-oriented functions to implement the stream-oriented functions, it suffices
to provide an implementation of the former. This allows Open Enclave to
indirectly provide the full set of stream-oriented functions listed below.

| stream-oriented functions |
| ------------------------- |
| clearerr()                |
| fclose()                  |
| fdopen()                  |
| feof()                    |
| ferror()                  |
| fflush()                  |
| fgetc()                   |
| fgetchar()                |
| fgetpos()                 |
| fgets()                   |
| fgets()                   |
| fgetwc()                  |
| fgetws()                  |
| fileno()                  |
| fopen()                   |
| fprintf()                 |
| fprintf()                 |
| fputc()                   |
| fputc()                   |
| fputs()                   |
| fread()                   |
| freopen()                 |
| fscanf()                  |
| fseek()                   |
| fseeko()                  |
| fsetpos()                 |
| ftell()                   |
| ftello()                  |
| fwrite()                  |
| getline()                 |
| putc()                    |
| rewind()                  |
| setbuf()                  |
| setvbuf()                 |
| ungetc()                  |
| vfprintf()                |
| vfscanf()                 |

### 2.2.3 The fd-oriented file I/O functions

Open Enclave provides full support for fd-oriented functions. For example:

```
    int fd;

    const int flags = OE_O_CREAT | OE_O_TRUNC | OE_O_WRONLY;
    const oe_mode_t mode = 0644;

    fd = open("/tmp/hello", flags, mode);
    ...
    oe_write(fd, "hello", 5);
    ...
    oe_close(fd);
```

Open Enclave does not implement these functions directly. Instead it uses the
MUSL implementation of these functions, which invoke **syscall()** with one
of the following system call numbers.

- **SYS_creat**
- **SYS_open**
- **SYS_lseek**
- **SYS_read**
- **SYS_readv**
- **SYS_write**
- **SYS_writev**
- **SYS_close**
- **SYS_stat**
- **SYS_link**
- **SYS_unlink**
- **SYS_rename**
- **SYS_truncate**
- **SYS_mkdir**
- **SYS_rmdir**
- **SYS_access**
- **SYS_ioctl**
- **SYS_fcntl**
- **SYS_socket**
- **SYS_accept**
- **SYS_connect**
- **SYS_listen**
- **SYS_shutdown**
- **SYS_bind**
- **SYS_getsockname**
- **SYS_getpeername**
- **SYS_getsockopt**
- **SYS_setsockopt**
- **SYS_select**
- **SYS_epoll_create**
- **SYS_epoll_wait**
- **SYS_epoll_ctl**

Open Enclave overrides the **syscall()** function, and handles the system call
by forwarding it to the devices framework.

### 2.2.4 The path-oriented file I/O functions

Open Enclave supports the following path-oriented functions by handling the
associated system call number as described in the previous section.

| path-oriented functions |
| ----------------------- |
| stat()                  |
| mkdir()                 |
| rmdir()                 |
| link()                  |
| unlink()                |
| remove()                |
| truncate()              |
| access()                |

Consider the following example.

```
    const char path[] = "/tmp/dir";
    struct stat buf;

    if (stat(path, &buf) && S_ISDIR(buf.st_mode))
    {
        rmdir(path);
    }
```


### 2.2.5 The directory-scanning functions

Open Enclave implements the standard POIX functions for scanning directories.
These functions are listed in the table below.

| directory-scanning functions |
| ---------------------------- |
| opendir()                    |
| readdir()                    |
| closedir()                   |

Consider the following example.

```
    const char path[] = "/tmp/dir";
    DIR* dir;
    struct dirent* ent;

    dir = opendir(path);

    while ((ent = readdir(dir)))
    {
        printf("filename=%s\n", ent->d_name);
    }

    closedir(dir);
```

### 2.2.6 The socket functions

Open Enclave implements most POSIX socket functions. These include:

| socket functions |
| ---------------- |
| socket()         |
| listen()         |
| connect()        |
| accept()         |
| shutdown()       |
| bind             |
| getsockname      |
| getpeername      |
| getsockopt       |
| setsockopt       |

- The socket functions (**socket()**, **connect()**, **send()**, etc.);

Consider the following client example.

```
    int sd;
    struct sockaddr_in addr;
    char buf[1024];

    sd = socket(AF_INET, SOCK_STREAM, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(OE_INADDR_LOOPBACK);
    addr.sin_port = htons(1492);
    connect(sd, (struct oe_sockaddr*)&addr, sizeof(addr));

    read(sd, buf, sizeof(buf));

    close(sd);
```

2.3 The IOT interface
---------------------

The IOT interface builds on the POSIX interface. It defines two custom header
files called **<stdio.h>** and **<socket.h>**. These header files include the
standard headers files with the same names. The IOT interface provides a
macro-driven interface. These interfaces existed prior to this work, so this
document does not describe them in detail.

The following example uses the IOT interface to create a secure file. This
example uses the oe-prefixed functions.

```
    #define OE_NO_POSIX_FILE_API /* Omit POSIX function macros. */
    #include <stdio.h> /* include customized IOT <stdio.h>. */

    const char path[] = "/tmp/myfile";
    OE_FILE* stream;
    const char secret[] = "my secret";

    stream = oe_fopen(OE_FILE_SECURE_ENCRYPTION, path, "w");

    oe_fwrite(secret, 1, sizeof(secret), stream);

    oe_fclose(stream);
```

The following example uses macros generated for **fopen()**, **fwrite()**, and
**fclose()**.

```
    #define OE_SECURE_POSIX_FILE_API /* Use secure file I/O */
    #include <stdio.h> /* include customized IOT <stdio.h>. */

    const char path[] = "/tmp/myfile";
    OE_FILE* stream;
    const char secret[] = "my secret";

    stream = fopen(path, "w");

    fwrite(secret, 1, sizeof(secret), stream);

    fclose(stream);
```

This example defines **OE_SECURE_POSIX_FILE_API** before including
**<stdio.h>**, which forces the macros for the POSIX functions to use
secure file I/O. The following shows how the macros are expanded when
**OE_SECURE_POSIX_FILE_API** is defined.

```
    fopen -> oe_fopen_OE_FILE_SECURE_BEST_EFFORT
    fwrite -> oe_fwrite
    fclose -> oe_fclose
```

When **OE_SECURE_POSIX_FILE_API** is not defined, the same macros are expanded
as follows.

```
    fopen -> oe_fopen_OE_FILE_INSECURE
    fwrite -> oe_fwrite
    fclose -> oe_fclose
```

3 Internal Design
=================

The device framework performs dispatching of operations to devices. Devices
are implemented as C structures that contain function pointers for each of
the supported operations listed below.

```
/*====================*/
/* Common operations. */
/*====================*/

int (*clone)(
    oe_device_t* device,
    oe_device_t** new_device);

int (*shutdown)(
    oe_device_t* dev);

int (*release)(
    oe_device_t* device);

int (*notify)(
    oe_device_t* device,
    uint64_t notification_mask);

ssize_t (*get_host_fd)(
    oe_device_t* device);

uint64_t (*ready_state)(
    oe_device_t* device);

ssize_t (*read)(
    oe_device_t* file,
    void* buf,
    size_t count);

ssize_t (*write)(
    oe_device_t* file,
    const void* buf,
    size_t count);

int (*close)(
    oe_device_t* file);

int (*ioctl)(
    oe_device_t* file,
    unsigned long request,
    oe_va_list ap);

/*=========================*/
/* File system operations. */
/*=========================*/

int (*mount)(
    oe_device_t* dev,
    const char* source,
    const char* target,
    uint32_t flags);

int (*unmount)(
    oe_device_t* dev,
    const char* target);

oe_device_t* (*open)(
    oe_device_t* dev,
    const char* pathname,
    int flags,
    mode_t mode);

off_t (*lseek)(
    oe_device_t* file,
    off_t offset,
    int whence);

oe_device_t* (*opendir)(
    oe_device_t* dev,
    const char* path);

struct oe_dirent* (*readdir)(
    oe_device_t* dir);

int (*closedir)(
    oe_device_t* dir);

int (*stat)(
    oe_device_t* dev,
    const char* pathname,
    struct oe_stat* buf);

int (*link)(
    oe_device_t* dev,
    const char* oldpath,
    const char* newpath);

int (*unlink)(
    oe_device_t* dev,
    const char* pathname);

int (*rename)(
    oe_device_t* dev,
    const char* oldpath,
    const char* newpath);

int (*truncate)(
    oe_device_t* dev,
    const char* path,
    off_t length);

int (*mkdir)(
    oe_device_t* dev,
    const char* pathname,
    mode_t mode);

int (*rmdir)(
    oe_device_t* dev,
    const char* pathname);

/*====================*/
/* Socket operations. */
/*====================*/

oe_device_t* (*socket)(
    oe_device_t* dev,
    int domain,
    int type,
    int protocol);

int (*connect)(
    oe_device_t* dev,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);

int (*accept)(
    oe_device_t* dev,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen);

int (*bind)(
    oe_device_t* dev,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);

int (*listen)(
    oe_device_t* dev,
    int backlog);

ssize_t (*recv)(
    oe_device_t* dev,
    void* buf,
    size_t len,
    int flags);

ssize_t (*send)(
    oe_device_t* dev,
    const void* buf,
    size_t len,
    int flags);

int (*shutdown)(
    oe_device_t* dev,
    int how);

int (*getsockopt)(
    oe_device_t* dev,
    int level,
    int optname,
    void* optval,
    oe_socklen_t* optlen);

int (*setsockopt)(
    oe_device_t* dev,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen);

int (*getpeername)(
    oe_device_t* dev,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen);

int (*getsockname)(
    oe_device_t* dev,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen);
```

Some of the operations above pertain to files, directories, or individual
sockets. That is because these objects themselves are represented as devices.

This section discusses device registration and device mapping.

3.1 Device registration
-----------------------

The devices already discussed are pre-registered. However, the device framework
is extensible and it is possible to define new device types. To do this, one
implements a device structure which implements either the file or socket
operations defined in the previous section. Next one must dynamically assign a
new **device id** as shown below.

```
    int devid;

    devid = oe_device_assign_devid();
```

Finally, the device must be registered as follows.

```
    oe_device_t* device; /* points to new device. */

    oe_device_register(devid, device);
```

This registers the new device.

3.2 Device dispatching
----------------------

Calls to certain functions must be resolved to a device that can handle
the operation. There are two methods used to resolve requests to devices:
direct-addressing and path-addressing.

3.2.1 Direct addressing
-----------------------

Direct addressing involves specifying the device id in the request. The
following example illustrates this.

```
    OE_FILE* stream;
    stream = oe_device_fopen(devid, path, "rb");
```

The device id is saved in thread-local storage so that when the dispatcher
handles the operations it will select that device.

3.2.1 Path addressing
---------------------

Path addressing involves specifying a path. To map paths to devices, the
mounting must be employed. The following example shows how to mount a path
and then use the associated device.

```
    FILE* stream;

    oe_mount(devid, NULL, "/mnt/somedir", 0);
    stream = fopen("/mnt/somedir/hello", "w");
    fwrite("hello", 1, 5, stream);
    fclose(stream);
```

Different devices may be mounted at different mount points. Requests on a path
whose suffix is such a mount pointer are delegated to that device.

Appendix A - Public headers
============================

The following are key public header files that have been published so far.

[**<device.h>**](../include/openenclave/bits/device.h)

[**<fs.h>**](../include/openenclave/bits/fs.h)

[**<in.h>**](../include/openenclave/bits/in.h)

[**<socket.h>**](../include/openenclave/bits/socket.h)

[**<socketaddr.h>**](../include/openenclave/bits/socketaddr.h)

Appendix B - Error reporting
============================

The Open Enclave I/O framework adopts the POSIX error numbers scheme. For
example:

```
    #include <errno.h>
    .
    .
    .
    ssize_t n;

    n = send(sd, buf, n);

    if (n == -1)
    {
        if (errno == EWOULDBLOCK)
        {
            ...
        }
    }
```

Equivalent names are provided for the OE namespace:

```
    #include <openenclave/corelib/errno.h>
    oe_errno
    OE_WOULDBLOCK
```
