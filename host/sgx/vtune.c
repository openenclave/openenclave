#ifdef VTUNE
#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <openenclave/internal/trace.h>
#include <string.h>
#include "enclave.h"
#include "vtune.h"

#include "ittnotify/ittnotify.h"
#include "ittnotify/ittnotify_config.h"
#include "ittnotify/ittnotify_types.h"

int __itt_init_ittlib(const char*, __itt_group_id);
__itt_global* __itt_get_ittapi_global();

#if defined(__linux__)

/*
** _write_process_mem, update_trust_thread_debug_flag, update_debug_flag
**
** These methods are helpers to set the TCS.FLAGS.DEBUGOPTIN bit
** in the process memory for each thread.
**
** The implementation takes reference of the linux-sgx source codes from Intel.
*/

static bool _write_process_mem(
    pid_t pid,
    void* base_addr,
    void* buffer,
    size_t size,
    size_t* write_nr)
{
    char filename[64];
    int fd = -1;
    int ret = false;
    ssize_t len = 0;
    off64_t offset = (off64_t)(size_t)base_addr;

    snprintf(filename, 64, "/proc/%d/mem", (int)pid);
    fd = open(filename, O_RDWR | O_LARGEFILE);
    if (fd == -1)
        return false;

    if (lseek64(fd, offset, SEEK_SET) == -1)
    {
        goto out;
    }
    if ((len = write(fd, buffer, size)) < 0)
    {
        goto out;
    }
    else if (write_nr)
        *write_nr = (size_t)len;
    ret = true;

out:
    close(fd);
    return ret;
}

static bool _update_trust_thread_debug_flag(sgx_tcs_t* tcs, uint8_t debug_flag)
{
    uint64_t debug_flag2 = (uint64_t)debug_flag;
    pid_t pid = getpid();

    return _write_process_mem(
        pid, &tcs->flags, &debug_flag2, sizeof(uint64_t), NULL);
}

static bool _update_debug_flag(oe_enclave_t* enclave, uint8_t debug_flag)
{
    if (enclave->debug)
    {
        for (uint64_t i = 0; i < enclave->num_bindings; ++i)
        {
            if (!_update_trust_thread_debug_flag(
                    (sgx_tcs_t*)enclave->bindings[i].tcs, debug_flag))
                return false;
        }
        return true;
    }
    return false;
}
#endif

/*
** This method encapsulates all steps of enabling vtune
** profiling in a loaded enclave application:
**     - Initialized the Instrumentation and Tracing Technology (ITT) library
**     - Verifies the API library is initialized globally
**     - Sets the debug flag for each TCS in process memory
**     - Loads the enclave module for tracing
**
** Make sure the following settings are configured:
**     - Sets -DVTUNE=1 flag when building the OpenEnclave SDK through cmake
**     - Sets the debug flag when creating the enclave
**     - Sets environment variable INTEL_LIBITTNOTIFY32
**        = <VTune Installation Dir>/lib32/runtime/ittnotify_collector.so
**     - Sets environment variable INTEL_LIBITTNOTIFY64
**        = <VTune Installation Dir>/lib64/runtime/ittnotify_collector.so
*/

bool enable_vtune_profiling(oe_enclave_t* enclave)
{
    if (enclave->debug)
    {
        __itt_init_ittlib(NULL, __itt_group_none);

        if (__itt_get_ittapi_global()->api_initialized &&
            __itt_get_ittapi_global()->lib)
        {
            /* Set debug flag for each thread */
            bool thread_updated = _update_debug_flag(enclave, 1);

            if (!thread_updated)
            {
                oe_log(OE_LOG_LEVEL_VERBOSE, "Failed to update debug flags\n");
            }
            else
            {
                oe_log(OE_LOG_LEVEL_VERBOSE, "Updated debug flags\n");
            }

            /* Load enclave module */
            oe_log(
                OE_LOG_LEVEL_VERBOSE, "VTune is profiling. Loading module.\n");

            uint64_t enclave_start_addr = enclave->addr;
            uint64_t enclave_end_addr = enclave_start_addr + enclave->size - 1;
            const char* enclave_path = (const char*)enclave->path;

            oe_log(
                OE_LOG_LEVEL_VERBOSE,
                "Invoking VTune's module mapping API __itt_module_load \n");
            oe_log(
                OE_LOG_LEVEL_VERBOSE,
                "Enclave_start_addr==0x%llx\n",
                enclave_start_addr);
            oe_log(
                OE_LOG_LEVEL_VERBOSE,
                "Enclave_end_addr==0x%llx\n",
                enclave_end_addr);
            oe_log(OE_LOG_LEVEL_VERBOSE, "Enclave_path==%s\n", enclave_path);

            __itt_module_load(
                (void*)enclave_start_addr,
                (void*)enclave_end_addr,
                enclave_path);

            return true;
        }
        else
        {
            oe_log(
                OE_LOG_LEVEL_VERBOSE,
                "ITT Global api not configured. VTune is not profiling.\n");
            return false;
        }
    }
    else
    {
        oe_log(
            OE_LOG_LEVEL_VERBOSE,
            "Debug flag not set for enclave. VTune is not profiling.\n");
        return false;
    }
}
#endif
