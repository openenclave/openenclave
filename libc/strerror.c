#include <string.h>
#include <errno.h>

typedef struct _ErrStr
{
    int num;
    const char* str;
}
ErrStr;

static ErrStr _errstr[] =
{
    { E2BIG, "Argument list too long" },
    { EACCES, "Permission denied" },
    { EADDRINUSE, "Address in use" },
    { EADDRNOTAVAIL, "Address not available" },
    { EAFNOSUPPORT, "Address family not supported" },
    { EAGAIN, "Resource unavailable, try again" },
    { EALREADY, "Connection already in progress" },
    { EBADF, "Bad file descriptor" },
    { EBADMSG, "Bad message" },
    { EBUSY, "Device or resource busy" },
    { ECANCELED, "Operation canceled" },
    { ECHILD, "No child processes" },
    { ECONNABORTED, "Connection aborted" },
    { ECONNREFUSED, "Connection refused" },
    { ECONNRESET, "Connection reset" },
    { EDEADLK, "Resource deadlock would occur" },
    { EDESTADDRREQ, "Destination address required" },
    { EDOM, "Math argument out of domain of function" },
    { EDQUOT, "Reserved" },
    { EEXIST, "File exists" },
    { EFAULT, "Bad address" },
    { EFBIG, "File too large" },
    { EHOSTUNREACH, "Host is unreachable" },
    { EIDRM, "Identifier removed" },
    { EILSEQ, "Illegal byte sequence" },
    { EINPROGRESS, "Operation in progress" },
    { EINTR, "Interrupted function" },
    { EINVAL, "Invalid argument" },
    { EIO, "I/O error" },
    { EISCONN, "Socket is connected" },
    { EISDIR, "Is a directory" },
    { ELOOP, "Too many levels of symbolic links" },
    { EMFILE, "Too many open files" },
    { EMLINK, "Too many links" },
    { EMSGSIZE, "Message too large" },
    { EMULTIHOP, "Reserved" },
    { ENAMETOOLONG, "Filename too long" },
    { ENETDOWN, "Network is down" },
    { ENETRESET, "Connection aborted by network" },
    { ENETUNREACH, "Network unreachable" },
    { ENFILE, "Too many files open in system" },
    { ENOBUFS, "No buffer space available" },
    { ENODATA, "No message available on STREAM queue" },
    { ENODEV, "No such device" },
    { ENOENT, "No such file or directory" },
    { ENOEXEC, "Executable file format error" },
    { ENOLCK, "No locks available" },
    { ENOLINK, "Reserved" },
    { ENOMEM, "Not enough space" },
    { ENOMSG, "No message of the desired type" },
    { ENOPROTOOPT, "Protocol not available" },
    { ENOSPC, "No space left on device" },
    { ENOSR, "No STREAM resources" },
    { ENOSTR, "Not a STREAM" },
    { ENOSYS, "Function not supported" },
    { ENOTCONN, "The socket is not connected" },
    { ENOTDIR, "Not a directory" },
    { ENOTEMPTY, "Directory not empty" },
    { ENOTSOCK, "Not a socket" },
    { ENOTSUP, "Not supported" },
    { ENOTTY, "Inappropriate I/O control operation" },
    { ENXIO, "No such device or address" },
    { EOPNOTSUPP, "Operation not supported on socket" },
    { EOVERFLOW, "Value too large to be stored in data type" },
    { EPERM, "Operation not permitted" },
    { EPIPE, "Broken pipe" },
    { EPROTO, "Protocol error" },
    { EPROTONOSUPPORT, "Protocol not supported" },
    { EPROTOTYPE, "Protocol wrong type for socket" },
    { ERANGE, "Result too large" },
    { EROFS, "Read-only file system" },
    { ESPIPE, "Invalid seek" },
    { ESRCH, "No such process" },
    { ESTALE, "Reserved" },
    { ETIME, "Stream ioctl() timeout" },
    { ETIMEDOUT, "Connection timed out" },
    { ETXTBSY, "Text file busy" },
    { EWOULDBLOCK, "Operation would block" },
    { EXDEV, "Cross-device link" },
};

static size_t nerrstr = sizeof(_errstr) / sizeof(_errstr[0]);

char* strerror(int errnum)
{
    for (size_t i = 0; i < nerrstr; i++)
    {
        if (errnum == _errstr[i].num)
            return (char*)_errstr[i].str;
    }

    return "Unknown error";
}
