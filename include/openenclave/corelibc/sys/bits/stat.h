// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__aarch64__)
struct __OE_STAT
{
    oe_dev_t st_dev;
    oe_ino_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    oe_uid_t st_uid;
    oe_gid_t st_gid;
    oe_dev_t st_rdev;
    unsigned int __st_pad1;
    oe_off_t st_size;
    int32_t st_blksize;
    oe_blkcnt_t st_blocks;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_atim;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_mtim;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_ctim;
    long unused;
};
#else
struct __OE_STAT
{
    oe_dev_t st_dev;
    oe_ino_t st_ino;
    oe_nlink_t st_nlink;
    oe_mode_t st_mode;
    oe_uid_t st_uid;
    oe_gid_t st_gid;
    unsigned int __st_pad0;
    oe_dev_t st_rdev;
    oe_off_t st_size;
    oe_blksize_t st_blksize;
    oe_blkcnt_t st_blocks;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_atim;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_mtim;
    struct
    {
        time_t tv_sec;
        suseconds_t tv_nsec;
    } st_ctim;
    long __st_unused[3];
};
#endif
