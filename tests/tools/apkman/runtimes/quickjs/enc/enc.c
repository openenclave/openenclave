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

#include <quickjs/quickjs-libc.h>
#include <quickjs/quickjs.h>

char code[10 * 1024];

char* get_code(char* arg)
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
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    {
        JSRuntime* rt = JS_NewRuntime();
        js_std_init_handlers(rt);
        js_std_set_worker_new_context_func(JS_NewContext);
        JSContext* ctx = JS_NewContext(rt);
        JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);
        js_std_add_helpers(ctx, argc - 1, argv + 1);

        for (int i = 1; i < argc; ++i)
        {
            char* code = get_code(argv[i]);
            int len = strlen(code);
            const char* filename = (argv[i] != code) ? argv[i] : "unnamed.js";
            int flags = JS_DetectModule(code, len) ? JS_EVAL_TYPE_MODULE
                                                   : JS_EVAL_TYPE_GLOBAL;

            JSValue val = JS_Eval(ctx, code, strlen(code), filename, flags);
            if (JS_IsException(val))
            {
                js_std_dump_error(ctx);
            }
            JS_FreeValue(ctx, val);
        }

        js_std_free_handlers(rt);
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
    }

    oe_umount("/");
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    true,  /* Debug */
    65536, /* NumHeapPages */
    1024,  /* NumStackPages */
    2);    /* NumTCS */
