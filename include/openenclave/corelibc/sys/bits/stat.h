// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
struct __OE_STAT
{
    oe_dev_t st_dev;            /* (0) */
    oe_ino_t st_ino;            /* (8) */
    oe_nlink_t st_nlink;        /* (16) */
    oe_mode_t st_mode;          /* (24) */
    oe_uid_t st_uid;            /* (28) */
    oe_gid_t st_gid;            /* (32) */
    uint32_t __st_pad0;         /* (36) */
    oe_dev_t st_rdev;           /* (40) */
    oe_off_t st_size;           /* (48) */
    oe_blksize_t st_blksize;    /* (56) */
    oe_blkcnt_t st_blocks;      /* (64) */
    struct
    {
        time_t tv_sec;          /* (72) */
        suseconds_t tv_nsec;    /* (80) */
    } st_atim;
    struct
    {
        time_t tv_sec;          /* (88) */
        suseconds_t tv_nsec;    /* (96) */
    } st_mtim;
    struct
    {
        time_t tv_sec;          /* (104) */
        suseconds_t tv_nsec;    /* (112) */
    } st_ctim;
};
// clang-format on

OE_STATIC_ASSERT((sizeof(struct __OE_STAT) % 8) == 0);
OE_STATIC_ASSERT(sizeof(struct __OE_STAT) == 120);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_dev) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_ino) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_nlink) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_mode) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_uid) == 28);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_gid) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_rdev) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_blksize) == 56);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_blocks) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_atim.tv_sec) == 72);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_atim.tv_nsec) == 80);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_mtim.tv_sec) == 88);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_mtim.tv_nsec) == 96);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_ctim.tv_sec) == 104);
OE_STATIC_ASSERT(OE_OFFSETOF(struct __OE_STAT, st_ctim.tv_nsec) == 112);
