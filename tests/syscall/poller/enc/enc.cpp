// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/sys/select.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/tests.h>
#include "../client.h"
#include "../server.h"

static void _init(void)
{
    static bool _initialized = false;

    if (!_initialized)
    {
        OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
        OE_TEST(oe_load_module_host_epoll() == OE_OK);
        _initialized = true;
    }
}

extern "C" void run_enclave_server(
    uint16_t port,
    size_t num_clients,
    uint32_t poller_type)
{
    _init();
    run_server(port, num_clients, poller_type_t(poller_type));
}

extern "C" void run_enclave_client(uint16_t port)
{
    _init();
    run_client(port);
}

extern "C" void test_fd_set(void)
{
    oe_fd_set set;

    /* Test clearing all bits. */
    {
        OE_FD_ZERO(&set);

        /* Test that all bits are cleared. */
        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_TEST(!OE_FD_ISSET(i, &set));

        /* Set all bits. */
        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_FD_SET(i, &set);

        /* Clear all bits. */
        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_FD_CLR(i, &set);

        /* Test that all bits are cleared. */
        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_TEST(!OE_FD_ISSET(i, &set));
    }

    /* Test setting all bits. */
    {
        OE_FD_ZERO(&set);

        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_FD_SET(i, &set);

        for (int i = 0; i < OE_FD_SETSIZE; i++)
            OE_TEST(OE_FD_ISSET(i, &set));
    }

    /* Test setting odd bits. */
    {
        OE_FD_ZERO(&set);

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            bool is_odd = (i % 2) != 0;

            if (is_odd)
                OE_FD_SET(i, &set);
            else
                OE_FD_CLR(i, &set);
        }

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            bool is_odd = (i % 2) != 0;

            if (is_odd)
                OE_TEST(OE_FD_ISSET(i, &set));
            else
                OE_TEST(!OE_FD_ISSET(i, &set));
        }
    }

    /* Test setting even bits. */
    {
        OE_FD_ZERO(&set);

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            bool is_even = (i % 2) == 0;

            if (is_even)
                OE_FD_SET(i, &set);
            else
                OE_FD_CLR(i, &set);
        }

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            bool is_even = (i % 2) == 0;

            if (is_even)
                OE_TEST(OE_FD_ISSET(i, &set));
            else
                OE_TEST(!OE_FD_ISSET(i, &set));
        }
    }

    /* Test setting prime bits. */
    {
        bool is_prime[OE_FD_SETSIZE];

        for (size_t i = 0; i < OE_FD_SETSIZE; i++)
            is_prime[i] = false;

        is_prime[2] = true;
        is_prime[3] = true;
        is_prime[5] = true;
        is_prime[7] = true;
        is_prime[11] = true;
        is_prime[13] = true;
        is_prime[17] = true;
        is_prime[19] = true;
        is_prime[23] = true;
        is_prime[29] = true;
        is_prime[31] = true;
        is_prime[37] = true;
        is_prime[41] = true;
        is_prime[43] = true;
        is_prime[47] = true;
        is_prime[53] = true;
        is_prime[59] = true;
        is_prime[61] = true;
        is_prime[67] = true;
        is_prime[71] = true;
        is_prime[73] = true;
        is_prime[79] = true;
        is_prime[83] = true;
        is_prime[89] = true;
        is_prime[97] = true;
        is_prime[101] = true;
        is_prime[103] = true;
        is_prime[107] = true;
        is_prime[109] = true;
        is_prime[113] = true;
        is_prime[127] = true;
        is_prime[131] = true;
        is_prime[137] = true;
        is_prime[139] = true;
        is_prime[149] = true;
        is_prime[151] = true;
        is_prime[157] = true;
        is_prime[163] = true;
        is_prime[167] = true;
        is_prime[173] = true;
        is_prime[179] = true;
        is_prime[181] = true;
        is_prime[191] = true;
        is_prime[193] = true;
        is_prime[197] = true;
        is_prime[199] = true;
        is_prime[211] = true;
        is_prime[223] = true;
        is_prime[227] = true;
        is_prime[229] = true;
        is_prime[233] = true;
        is_prime[239] = true;
        is_prime[241] = true;
        is_prime[251] = true;
        is_prime[257] = true;
        is_prime[263] = true;
        is_prime[269] = true;
        is_prime[271] = true;
        is_prime[277] = true;
        is_prime[281] = true;
        is_prime[283] = true;
        is_prime[293] = true;
        is_prime[307] = true;
        is_prime[311] = true;
        is_prime[313] = true;
        is_prime[317] = true;
        is_prime[331] = true;
        is_prime[337] = true;
        is_prime[347] = true;
        is_prime[349] = true;
        is_prime[353] = true;
        is_prime[359] = true;
        is_prime[367] = true;
        is_prime[373] = true;
        is_prime[379] = true;
        is_prime[383] = true;
        is_prime[389] = true;
        is_prime[397] = true;
        is_prime[401] = true;
        is_prime[409] = true;
        is_prime[419] = true;
        is_prime[421] = true;
        is_prime[431] = true;
        is_prime[433] = true;
        is_prime[439] = true;
        is_prime[443] = true;
        is_prime[449] = true;
        is_prime[457] = true;
        is_prime[461] = true;
        is_prime[463] = true;
        is_prime[467] = true;
        is_prime[479] = true;
        is_prime[487] = true;
        is_prime[491] = true;
        is_prime[499] = true;
        is_prime[503] = true;
        is_prime[509] = true;
        is_prime[521] = true;
        is_prime[523] = true;
        is_prime[541] = true;
        is_prime[547] = true;
        is_prime[557] = true;
        is_prime[563] = true;
        is_prime[569] = true;
        is_prime[571] = true;
        is_prime[577] = true;
        is_prime[587] = true;
        is_prime[593] = true;
        is_prime[599] = true;
        is_prime[601] = true;
        is_prime[607] = true;
        is_prime[613] = true;
        is_prime[617] = true;
        is_prime[619] = true;
        is_prime[631] = true;
        is_prime[641] = true;
        is_prime[643] = true;
        is_prime[647] = true;
        is_prime[653] = true;
        is_prime[659] = true;
        is_prime[661] = true;
        is_prime[673] = true;
        is_prime[677] = true;
        is_prime[683] = true;
        is_prime[691] = true;
        is_prime[701] = true;
        is_prime[709] = true;
        is_prime[719] = true;
        is_prime[727] = true;
        is_prime[733] = true;
        is_prime[739] = true;
        is_prime[743] = true;
        is_prime[751] = true;
        is_prime[757] = true;
        is_prime[761] = true;
        is_prime[769] = true;
        is_prime[773] = true;
        is_prime[787] = true;
        is_prime[797] = true;
        is_prime[809] = true;
        is_prime[811] = true;
        is_prime[821] = true;
        is_prime[823] = true;
        is_prime[827] = true;
        is_prime[829] = true;
        is_prime[839] = true;
        is_prime[853] = true;
        is_prime[857] = true;
        is_prime[859] = true;
        is_prime[863] = true;
        is_prime[877] = true;
        is_prime[881] = true;
        is_prime[883] = true;
        is_prime[887] = true;
        is_prime[907] = true;
        is_prime[911] = true;
        is_prime[919] = true;
        is_prime[929] = true;
        is_prime[937] = true;
        is_prime[941] = true;
        is_prime[947] = true;
        is_prime[953] = true;
        is_prime[967] = true;
        is_prime[971] = true;
        is_prime[977] = true;
        is_prime[983] = true;
        is_prime[991] = true;
        is_prime[997] = true;
        is_prime[1009] = true;
        is_prime[1013] = true;
        is_prime[1019] = true;
        is_prime[1021] = true;

        OE_FD_ZERO(&set);

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            if (is_prime[i])
                OE_FD_SET(i, &set);
            else
                OE_FD_CLR(i, &set);
        }

        for (int i = 0; i < OE_FD_SETSIZE; i++)
        {
            if (is_prime[i])
                OE_TEST(OE_FD_ISSET(i, &set));
            else
                OE_TEST(!OE_FD_ISSET(i, &set));
        }
    }

    oe_printf("==== passed %s\n", __FUNCTION__);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    9);   /* NumTCS */
