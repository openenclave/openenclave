// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void test_ids(
    pid_t pid,
    pid_t ppid,
    uid_t uid,
    uid_t euid,
    gid_t gid,
    gid_t egid,
    pid_t pgrp,
    const gid_t* groups,
    size_t num_groups)
{
    gid_t list[NGROUPS_MAX];

    memset(list, 0xff, sizeof(list));

    /* This cannot possibly be the init process. */
    OE_TEST(getpid() != 0);

    OE_TEST(getpid() == pid);
    OE_TEST(getppid() == ppid);
    OE_TEST(getuid() == uid);
    OE_TEST(geteuid() == euid);
    OE_TEST(getgid() == gid);
    OE_TEST(getegid() == egid);
    OE_TEST(getpgrp() == pgrp);
    OE_TEST(getgroups(0, NULL) == (int)num_groups);
    OE_TEST(getgroups((int)num_groups, list) == (int)num_groups);
    OE_TEST(memcmp(groups, list, num_groups * sizeof(gid_t)) == 0);

    OE_UNUSED(groups);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
