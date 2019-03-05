// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* struct stat fields. */
#if defined(__aarch64__)
dev_t st_dev;     /* Device.  */
ino64_t st_ino;   /* File serial number. */
mode_t st_mode;   /* File mode.  */
nlink_t st_nlink; /* Link count.  */
uid_t st_uid;     /* User ID of the file's owner. */
gid_t st_gid;     /* Group ID of the file's group.*/
dev_t st_rdev;    /* Device number, if device.  */
dev_t __pad1;
off64_t st_size;      /* Size of file, in bytes. */
blksize_t st_blksize; /* Optimal block size for I/O.  */
int __pad2;
blkcnt64_t st_blocks; /* 512-byte blocks */
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
int __reserved[2];
#else
dev_t st_dev;
ino_t st_ino;
nlink_t st_nlink;
mode_t st_mode;
uid_t st_uid;
gid_t st_gid;
unsigned int __st_pad0;
dev_t st_rdev;
off_t st_size;
blksize_t st_blksize;
blkcnt_t st_blocks;
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
#endif
