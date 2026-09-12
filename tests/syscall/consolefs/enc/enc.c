// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include "consolefs_t.h"

static bool _termios_flags_equal(
    const struct termios* a,
    const struct termios* b)
{
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag &&
           a->c_cflag == b->c_cflag && a->c_lflag == b->c_lflag;
}

void test_consolefs()
{
    // test ioctl
    struct termios t1 = {0};
    struct termios t2 = {0};
    OE_TEST(ioctl(STDIN_FILENO, TCGETS, &t1) == 0);
    OE_TEST(!_termios_flags_equal(&t1, &t2));
    OE_TEST(ioctl(STDIN_FILENO, TCSETS, &t1) == 0);
    OE_TEST(ioctl(STDIN_FILENO, TCGETS, &t2) == 0);
    OE_TEST(_termios_flags_equal(&t1, &t2));
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    512,  /* NumStackPages */
    1);   /* NumTCS */
