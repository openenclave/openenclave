#ifndef TEST_MBED_MYFILEIO_H
#define TEST_MBED_MYFILEIO_H

#if defined(_WIN32)
    #include <io.h>
    #include <process.h>
    #include <direct.h>
    typedef unsigned mode_t;
#else
    #include <sys/uio.h>
    #include <unistd.h>
#endif

#endif /* TEST_MBED_MYFILEIO_H */