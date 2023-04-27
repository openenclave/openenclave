// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openssl/engine.h>
#include <string.h>
#include <sys/mount.h>
#include "openssl_t.h"
#include "tu_local.h" /* Header from openssl/test/testutil */

extern char** __environ;

extern int main(int argc, char* argv[]);

void register_pthread_hooks(void);

int enc_test(int argc, char** argv, char** env)
{
    int ret = 1;
    const BIO_METHOD* tap = NULL;

    /* Register pthread hooks. Used only by threadstest */
    register_pthread_hooks();

    /* Directly use environ from host. */
    __environ = env;

    /* Initialize socket and host fs. */
    if (oe_load_module_host_socket_interface() != OE_OK)
        goto done;

    if (oe_load_module_host_resolver() != OE_OK)
        goto done;

#ifndef CODE_COVERAGE
    /*
     * When enabling code coverage analysis, libgcov should initialize the host
     * fs already so we do not do it again here. Otherwise, the
     * oe_load_module_host_file_system will fail.
     */
    if (oe_load_module_host_file_system() != OE_OK)
        goto done;
    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL))
        goto done;
#endif

    /*
     * In test 'ec_internal_test', a file is created locally without
     * providing an absolute path to fopen() systemcall. This causes
     * the test to fail in linux. Mounting the current binary directory
     * to root enables the filepath to be recognized by the OE's fopen()
     * call.
     *
     * NOTE: OE in Windows works fine without the need for absolute path
     * in fopen(). Mounting the current binary directory causes
     * oe_resolve_mount() to fail.
     */
    if (argc == 2 && strstr(argv[0], "ec_internal_test"))
    {
        umount("/");
        if (mount(argv[argc - 1], "/", OE_HOST_FILE_SYSTEM, 0, NULL))
            goto done;
    }

    /*
     * Hold the reference to the tap method that is used by the OpenSSL test
     * framework such that we can free it (which the framework does not do
     * that). Without doing this, DEBUG_MALLOC will report memory leaks.
     */
#if OECRYPTO_OPENSSL_VER < 3
    tap = BIO_f_tap();
#endif

    /* Perform the test. */
    ret = main(argc, argv);

done:
#ifndef CODE_COVERAGE // Avoid conflicts with libgcov.
    umount("/");
#endif
    if (__environ)
        __environ = NULL;

    if (tap)
        BIO_meth_free((BIO_METHOD*)tap);

    return ret;
}

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    ({0}), /* ExtendedProductID */
    ({0}), /* FamilyID */
    true,  /* Debug */
    true,  /* CapturePFGPExceptions */
    false, /* RequireKSS */
    false, /* CreateZeroBaseEnclave */
    0,     /* StartAddress */
    7200,  /* NumHeapPages */
    128,   /* NumStackPages */
    8);    /* NumTCS */
