// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

// For mounting host filesystem
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <sys/mount.h>

#include "test_t.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

char code[10 * 1024];

const char* get_code(const char* arg)
{
    FILE* f = fopen(arg, "r");
    if (f)
    {
        fread(code, 1, sizeof(code), f);
        fclose(f);
        return code;
    }
    else
        return arg;
}

/* compress or decompress from stdin to stdout */
int enc_main(int argc, char** argv)
{
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    int ret = -1;
    bool mounted = false;

    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);
    mounted = true;

    {
        lua_State* l = luaL_newstate();
        // Open standard libraries.
        luaL_openlibs(l);

        for (int i = 1; i < argc; ++i)
        {
            const char* code = get_code(argv[i]);
            if (luaL_loadbuffer(l, code, strlen(code), "argument"))
            {
                fprintf(
                    stderr,
                    "lua couldn't parse '%s': %s.\n",
                    argv[i],
                    lua_tostring(l, -1));
                lua_pop(l, 1);
            }
            else
            {
                if (lua_pcall(l, 0, 1, 0))
                {
                    fprintf(
                        stderr,
                        "lua couldn't execute '%s': %s.\n",
                        argv[i],
                        lua_tostring(l, -1));
                    lua_pop(l, 1);
                }
                else
                {
                    lua_pop(l, lua_gettop(l));
                }
            }
        }

        /* Remember to destroy the Lua State */
        lua_close(l);
    }

    ret = 0;
    goto done;
done:
    if (mounted)
        oe_umount("/");

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    true,  /* Debug */
    65536, /* NumHeapPages */
    1024,  /* NumStackPages */
    2);    /* NumTCS */
