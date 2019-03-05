// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/internal/fs.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>

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

oe_device_t* oe_mount_resolve(const char* path, char suffix[OE_PATH_MAX])
{
    oe_device_t* ret = NULL;
    size_t match_len = 0;
    char realpath[OE_PATH_MAX];

    if (!path || !suffix)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* First check whether a device id is set for this thread. */
    {
        uint64_t devid;

        if ((devid = oe_get_thread_device()) != OE_DEVID_NULL)
        {
            oe_device_t* device = oe_get_devid_device(devid);

            if (!device || device->type != OE_DEVICETYPE_FILESYSTEM)
            {
                oe_errno = EINVAL;
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
        goto done;

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
        oe_errno = ENOENT;

done:
    return ret;
}

static oe_device_t* _filesystemtype_to_device(const char* filesystemtype)
{
    oe_device_t* ret = NULL;
    struct pair
    {
        const char* filesystemtype;
        uint64_t devid;
    };
    struct pair pairs[] = {
        {"hostfs", OE_DEVID_HOSTFS},
        {"sgxfs", OE_DEVID_SGXFS},
        {"shwfs", OE_DEVID_SHWFS},
    };
    static const size_t num_pairs = OE_COUNTOF(pairs);
    size_t i;
    uint64_t devid = OE_DEVID_NULL;

    for (i = 0; i < num_pairs; i++)
    {
        if (oe_strcmp(pairs[i].filesystemtype, filesystemtype) == 0)
        {
            devid = pairs[i].devid;
            break;
        }
    }

    if (devid == OE_DEVID_NULL)
        goto done;

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
    oe_device_t* device = _filesystemtype_to_device(filesystemtype);
    oe_device_t* new_device = NULL;
    bool locked = false;

    OE_UNUSED(data);

    if (!device || device->type != OE_DEVICETYPE_FILESYSTEM || !target)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Be sure the full_target directory exists (if not root). */
    if (oe_strcmp(target, "/") != 0)
    {
        struct oe_stat buf;

        if (oe_stat(target, &buf) != 0)
        {
            oe_errno = EIO;
            goto done;
        }

        if (!OE_S_ISDIR(buf.st_mode))
        {
            oe_errno = ENOTDIR;
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
        goto done;
    }

    /* Reject duplicate mount paths. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        if (oe_strcmp(_mount_table[i].path, target) == 0)
        {
            oe_errno = EEXIST;
            goto done;
        }
    }

    /* Clone the device. */
    if (device->ops.fs->base.clone(device, &new_device) != 0)
    {
        oe_errno = ENOMEM;
        goto done;
    }

    /* Assign and initialize new mount point. */
    {
        size_t index = _mount_table_size;
        size_t len = oe_strlen(target);

        if (!(_mount_table[index].path = oe_malloc(len + 1)))
        {
            oe_errno = ENOMEM;
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

    oe_spin_lock(&_lock);

    OE_UNUSED(flags);

    if (!device || device->type != OE_DEVICETYPE_FILESYSTEM || !target)
    {
        oe_errno = EINVAL;
        goto done;
    }

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
        goto done;
    }

    /* Remove the entry by swapping with the last entry. */
    {
        oe_device_t* fs = _mount_table[index].fs;

        oe_free(_mount_table[index].path);
        fs = _mount_table[index].fs;
        _mount_table[index] = _mount_table[_mount_table_size - 1];
        _mount_table_size--;

        if (fs->ops.fs->unmount(fs, target) != 0)
            goto done;

        fs->ops.fs->base.release(fs);
    }

    ret = 0;

done:

    oe_spin_unlock(&_lock);
    return ret;
}

int oe_umount(const char* target)
{
    return oe_umount2(target, 0);
}
