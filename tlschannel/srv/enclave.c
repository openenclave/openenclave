// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "tlssrv.h"
#include "tlssrv_t.h"

#define MRENCLAVE_SIZE 32
#define MRSIGNER_SIZE 32
#define ISVPRODID_SIZE 16

static void _err_exit(const tlssrv_err_t* err)
{
    tlssrv_put_err(err);
    exit(1);
}

static void _dump(const char* msg, const uint8_t* data, size_t size)
{
    printf("%s: ", msg);

    for (size_t i = 0; i < size; i++)
    {
        printf("%02x", data[i]);

        if (i + 1 != size)
            printf(" ");
    }

    printf("\n");
}

static oe_result_t _verify_identity(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn)
{
    const uint64_t ISVSVN = 3;
    const uint8_t ISVPRODID[ISVPRODID_SIZE] = {2};
    // clang-format off
    const uint8_t MRSIGNER[] =
    {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
        0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
        0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
        0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0x0a
    };
    // clang-format on

    (void)arg;

    if (!mrenclave || !mrsigner || !isvprodid)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrenclave_size != MRENCLAVE_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrsigner_size != MRSIGNER_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (isvprodid_size != ISVPRODID_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    printf("\n");
    printf("=== _verify_identity()\n");
    _dump("MRENCLAVE", mrenclave, mrenclave_size);
    _dump("MRSIGNER", mrsigner, mrsigner_size);
    _dump("ISVPRODID", isvprodid, isvprodid_size);
    printf("ISVSVN: %lu\n", isvsvn);
    printf("\n");

    if (memcmp(isvprodid, ISVPRODID, ISVPRODID_SIZE) != 0)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (memcmp(mrsigner, MRSIGNER, MRSIGNER_SIZE) != 0)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (isvsvn != ISVSVN)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    /* ATTN: verify identity here!!! Return OE_OK or OE_VERIFY_FAILED */
    return OE_OK;
}

static int _run_server(void)
{
    int r;
    tlssrv_t* srv = NULL;
    tlssrv_err_t err;
    const char* ip = "127.0.0.1";
    const char* port = "12345";
    mbedtls_net_context conn;

    if ((r = tlssrv_startup(&err)) != 0)
        _err_exit(&err);

    if ((r = tlssrv_create(ip, port, _verify_identity, NULL, &srv, &err)) != 0)
    {
        _err_exit(&err);
    }

    /* Wait for connections */
    for (;;)
    {
        /* Accept the next client connection */
        if ((r = tlssrv_accept(srv, &conn, &err)) != 0)
            _err_exit(&err);

        /* Handle this connection */
        for (;;)
        {
            char buf[1024];
            size_t nbytes;

            if ((r = tlssrv_read(srv, buf, sizeof(buf), &err)) <= 0)
            {
                if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                {
                    mbedtls_net_free(&conn);
                    break;
                }

                _err_exit(&err);
            }

            nbytes = (size_t)r;

            if ((r = tlssrv_write(srv, buf, nbytes, &err)) <= 0)
                _err_exit(&err);
        }
    }

    if ((r = tlssrv_destroy(srv, &err)) != 0)
        _err_exit(&err);

    if ((r = tlssrv_shutdown(&err)) != 0)
        _err_exit(&err);

    return 0;
}

int tlssrv_run_server_ecall(void)
{
    if (oe_load_module_host_socket_interface() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_socket_interface() failed\n");
        return -1;
    }

    if (oe_load_module_host_resolver() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_resolver() failed\n");
        return -1;
    }

    return _run_server();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
