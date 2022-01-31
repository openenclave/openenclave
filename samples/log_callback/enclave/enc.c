// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/tracee.h>
#include <stdio.h>
#include <string.h>

// Include the trusted log_callback header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the log_callback.edl file.
#include "log_callback_t.h"

void enclave_customized_log(
    void* context,
    oe_log_level_t level,
    uint64_t thread_id,
    const char* message)
{
    char modified_log[200];

    sprintf(
        modified_log,
        "E, %s, %llx, %s",
        oe_log_level_strings[level],
        thread_id,
        message);

    /*
     * Add logic here to modify the log message, to obscure enclave logs from
     * the host. The context might be used, for example, to transfer a
     * shared/public/private secret, that may be used to encrypt the log
     * message.
     */
    fprintf((FILE*)context, "%s\n", modified_log);
}

FILE* enc_logfile = NULL;

void enclave_set_log_callback(const char* abs_filepath)
{
    oe_result_t result;

    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_file_system() failed\n");
        exit(1);
    }

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    if (!(enc_logfile = fopen(abs_filepath, "w")))
        fprintf(stderr, "fopen failed %s\n", abs_filepath);

    oe_enclave_log_set_callback((void*)enc_logfile, enclave_customized_log);
}

void enclave_hostfs_unmount()
{
    fclose(enc_logfile);
    umount("/");
}

// This is the function that the host calls. It prints
// a message in the enclave before calling back out to
// the host to print a message from there too.
void enclave_hello()
{
    // Call back into the host
    oe_result_t result = host_hello();
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "Call to host_hello failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
}
