// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/corelibc/limits.h>

#define MAX_MOUNT_TABLE_SIZE 64

typedef struct _mount_point
{
    char* path;
    oe_device_t* fs;
    uint32_t flags;
} mount_point_t;

static mount_point_t _mount_table[MAX_MOUNT_TABLE_SIZE];
size_t _mount_table_size = 0;
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

static bool _installed_free_mount_table = false;

static void _free_mount_table(void)
{
    for (size_t i = 0; i < _mount_table_size; i++)
        oe_free(_mount_table[i].path);
}

static oe_once_t _tls_device_once = OE_ONCE_INIT;
static oe_thread_key_t _tls_device_key = OE_THREADKEY_INITIALIZER;

static void _create_tls_device_key()
{
    if (oe_thread_key_create(&_tls_device_key, NULL) != 0)
        oe_abort();
}

static int _set_tls_device(uint64_t devid)
{
    int ret = -1;
    oe_result_t result = OE_FAILURE;

    if (devid == OE_DEVID_NONE)
    {
        OE_TRACE_ERROR("devid is OE_DEVID_NONE");
        goto done;
    }

    if ((result = oe_once(&_tls_device_once, _create_tls_device_key)) != OE_OK)
    {
        OE_TRACE_ERROR("devid=%lu result=%s", devid, oe_result_str(result));
        goto done;
    }

    if ((result = oe_thread_setspecific(_tls_device_key, (void*)devid)) !=
        OE_OK)
    {
        OE_TRACE_ERROR("devid=%lu result=%s", devid, oe_result_str(result));
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static int _clear_tls_device(void)
{
    int ret = -1;
    oe_result_t result = OE_FAILURE;

    if ((result = oe_once(&_tls_device_once, _create_tls_device_key)) != OE_OK)
    {
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }

    if ((result = oe_thread_setspecific(_tls_device_key, NULL)) != OE_OK)
    {
        OE_TRACE_ERROR("%s", oe_result_str(result));
        goto done;
    }
    ret = 0;
done:
    return ret;
}

static uint64_t _get_tls_device(void)
{
    uint64_t ret = OE_DEVID_NONE;
    uint64_t devid;

    if (oe_once(&_tls_device_once, _create_tls_device_key) != 0)
        goto done;

    if (!(devid = (uint64_t)oe_thread_getspecific(_tls_device_key)))
        goto done;

    ret = devid;

done:
    return ret;
}
oe_device_t* oe_mount_resolve(const char* path, char suffix[OE_PATH_MAX])
{
    oe_device_t* ret = NULL;
    size_t match_len = 0;
    char realpath[OE_PATH_MAX];

    if (!path || !suffix)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* First check whether a device id is set for this thread. */
    {
        uint64_t devid;

        if ((devid = _get_tls_device()) != OE_DEVID_NONE)
        {
            oe_device_t* device = oe_get_devid_device(devid);

            if (!device || device->type != OE_DEVICE_TYPE_FILESYSTEM)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }

            /* Use this device. */
            oe_strlcpy(suffix, path, OE_PATH_MAX);
            ret = device;
            goto done;
        }
    }

    /* Find the real path (the absolute non-relative path). */
    if (!oe_realpath(path, realpath))
    {
        OE_TRACE_ERROR("path = %s realpath=%s", path, realpath);
        goto done;
    }

    oe_spin_lock(&_lock);
    {
        /* Find the longest binding point that contains this path. */
        for (size_t i = 0; i < _mount_table_size; i++)
        {
            size_t len = oe_strlen(_mount_table[i].path);
            const char* mpath = _mount_table[i].path;

            if (mpath[0] == '/' && mpath[1] == '\0')
            {
                if (len > match_len)
                {
                    if (suffix)
                    {
                        oe_strlcpy(suffix, realpath, OE_PATH_MAX);
                    }

                    match_len = len;
                    ret = _mount_table[i].fs;
                }
            }
            else if (
                oe_strncmp(mpath, realpath, len) == 0 &&
                (realpath[len] == '/' || realpath[len] == '\0'))
            {
                if (len > match_len)
                {
                    if (suffix)
                    {
                        oe_strlcpy(suffix, realpath + len, OE_PATH_MAX);

                        if (*suffix == '\0')
                            oe_strlcpy(suffix, "/", OE_PATH_MAX);
                    }

                    match_len = len;
                    ret = _mount_table[i].fs;
                }
            }
        }
    }
    oe_spin_unlock(&_lock);

    if (!ret)
    {
        oe_errno = ENOENT;
        OE_TRACE_ERROR("oe_errno=%d path={%s}", oe_errno, path);
    }

done:
    return ret;
}

static oe_device_t* _filesystemtype_to_device(
    const char* filesystemtype,
    uint64_t* devid_out)
{
    oe_device_t* ret = NULL;
    struct pair
    {
        const char* filesystemtype;
        uint64_t devid;
    };
    struct pair pairs[] = {
        {"hostfs", OE_DEVID_HOSTFS},
    };
    static const size_t num_pairs = OE_COUNTOF(pairs);
    size_t i;
    uint64_t devid = OE_DEVID_NONE;

    if (devid_out)
        *devid_out = OE_DEVID_NONE;

    for (i = 0; i < num_pairs; i++)
    {
        if (oe_strcmp(pairs[i].filesystemtype, filesystemtype) == 0)
        {
            devid = pairs[i].devid;
            break;
        }
    }

    if (devid == OE_DEVID_NONE)
    {
        OE_TRACE_ERROR("devid is OE_DEVID_NONE");
        goto done;
    }

    *devid_out = devid;
    ret = oe_get_devid_device(devid);

done:
    return ret;
}

int oe_mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data)
{
    int ret = -1;
    uint64_t devid = OE_DEVID_NONE;
    oe_device_t* device = NULL;
    oe_device_t* new_device = NULL;
    bool locked = false;
    int retval = -1;

    if (!target)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Resolve the device and the devid if filesystemtype present. */
    if (filesystemtype)
    {
        device = _filesystemtype_to_device(filesystemtype, &devid);

        if (!device)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    /* Set special thread-local-storage device just for this thread. */
    if (oe_strcmp(target, "__tls__") == 0)
    {
        /* Resolve devid if not already resolved. */
        if (devid == OE_DEVID_NONE)
        {
            if (!data)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }

            devid = *((uint64_t*)data);

            if (!oe_get_devid_device(devid))
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }
        }

        /* Use this devid for all requests on this thread. */

        if ((retval = _set_tls_device(devid)) != 0)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        ret = 0;
        goto done;
    }

    /* If the device has not been resolved. */
    if (!device || device->type != OE_DEVICE_TYPE_FILESYSTEM)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Be sure the full_target directory exists (if not root). */
    if (oe_strcmp(target, "/") != 0)
    {
        struct oe_stat buf;
        int retval = -1;

        if ((retval = oe_stat(target, &buf)) != 0)
        {
            oe_errno = EIO;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if (!OE_S_ISDIR(buf.st_mode))
        {
            oe_errno = ENOTDIR;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    /* Lock the mount table. */
    oe_spin_lock(&_lock);
    locked = true;

    /* Install _free_mount_table() if not already installed. */
    if (_installed_free_mount_table == false)
    {
        oe_atexit(_free_mount_table);
        _installed_free_mount_table = true;
    }

    /* Fail if mount table exhausted. */
    if (_mount_table_size == MAX_MOUNT_TABLE_SIZE)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Reject duplicate mount paths. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        retval = oe_strcmp(_mount_table[i].path, target);
        if (retval == 0)
        {
            oe_errno = EEXIST;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    /* Clone the device. */
    retval = device->ops.fs->base.clone(device, &new_device);
    if (retval != 0)
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Assign and initialize new mount point. */
    {
        size_t index = _mount_table_size;
        size_t len = oe_strlen(target);

        _mount_table[index].path = oe_malloc(len + 1);

        if (!_mount_table[index].path)
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        memcpy(_mount_table[index].path, target, len + 1);
        _mount_table[index].fs = new_device;
        _mount_table_size++;
    }

    /* Notify the device that it has been mounted. */
    if (new_device->ops.fs->mount(new_device, source, target, mountflags) != 0)
    {
        oe_free(_mount_table[--_mount_table_size].path);
        goto done;
    }

    new_device = NULL;
    ret = 0;

done:

    if (new_device)
        new_device->ops.fs->base.release(new_device);

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_umount2(const char* target, int flags)
{
    int ret = -1;
    size_t index = (size_t)-1;
    char suffix[OE_PATH_MAX];
    oe_device_t* device = oe_mount_resolve(target, suffix);
    bool locked = false;

    OE_UNUSED(flags);

    if (!device || device->type != OE_DEVICE_TYPE_FILESYSTEM || !target)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Handle special case of unmounting the thread-local-storage device. */
    if (oe_strcmp(target, "__tls__") == 0)
    {
        if (_clear_tls_device() != 0)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        ret = 0;
        goto done;
    }

    oe_spin_lock(&_lock);
    locked = true;

    /* Find and remove this device. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        if (oe_strcmp(_mount_table[i].path, target) == 0)
        {
            index = i;
            break;
        }
    }

    /* If mount point not found. */
    if (index == (size_t)-1)
    {
        oe_errno = ENOENT;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Remove the entry by swapping with the last entry. */
    {
        oe_device_t* fs = _mount_table[index].fs;
        int retval = -1;

        oe_free(_mount_table[index].path);
        fs = _mount_table[index].fs;
        _mount_table[index] = _mount_table[_mount_table_size - 1];
        _mount_table_size--;

        if ((retval = fs->ops.fs->unmount(fs, target)) != 0)
        {
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        fs->ops.fs->base.release(fs);
    }

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_umount(const char* target)
{
    return oe_umount2(target, 0);
}
