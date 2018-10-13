/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <tcps_u.h>
#include "TcpsCalls_u.h"
#include <sgx.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#ifdef _MSC_VER
# include <Shlobj.h>
# include <time.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
static void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
            {
                printf("Info: %s\n", sgx_errlist[idx].sug);
            }
            printf("Error %#x: %s\n", ret, sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    {
        printf("Error: Unexpected error %#x occurred.\n", ret);
    }
}

static int query_sgx_status()
{
    sgx_device_status_t sgx_device_status;
    sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
    if (sgx_ret != SGX_SUCCESS)
    {
        printf("Failed to get SGX device status.\n");
        return -1;
    }
    else
    {
        switch (sgx_device_status)
        {
        case SGX_ENABLED:
            return 0;
        case SGX_DISABLED_REBOOT_REQUIRED:
            printf("SGX device has been enabled. Please reboot your machine.\n")
                ;
            return -1;
        case SGX_DISABLED_LEGACY_OS:
            printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
                return -1;
        case SGX_DISABLED:
            printf("SGX is not enabled on this platform. More details are unavailable.\n");
                return -1;
        case SGX_DISABLED_SCI_AVAILABLE:
            printf("SGX device can be enabled by a Software Control Interface.\n");
                return -1;
        case SGX_DISABLED_MANUAL_ENABLE:
            printf("SGX device can be enabled manually in the BIOS setup.\n");
            return -1;
        case SGX_DISABLED_HYPERV_ENABLED:
            printf("Detected an unsupported version of Windows* 10 with Hyper-V enabled.\n");
                return -1;
        case SGX_DISABLED_UNSUPPORTED_CPU:
            printf("SGX is not supported by this CPU.\n");
            return -1;
        default:
            printf("Unexpected error.\n");
            return -1;
        }
    }
}

/* Initialize the enclave:
*   Step 1: try to retrieve the launch token saved by last transaction
*   Step 2: call sgx_create_enclave to initialize an enclave instance
*   Step 3: save the launch token if it is updated
*/
static int initialize_enclave(
    _In_z_ const char* token_filename, 
    _In_z_ const char* enclave_filename, 
    _In_ uint32_t flags,
    _Out_ sgx_enclave_id_t* peid)
{
    char token_path[MAX_PATH] = { '\0' };
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    char appName[256];
    strcpy_s(appName, sizeof(appName), token_filename);
    char *p = strrchr(appName, '.');
    if (p != NULL) {
        *p = 0;
    }

    /* Step 1: try to retrieve the launch token saved by last transaction
    *         if there is no token, then create a new one.
    */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) { strcpy_s(token_path, _countof(token_path), token_filename);
    } else {
        strcat_s(token_path, _countof(token_path), "\\");
        strcat_s(token_path, _countof(token_path), token_filename);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        (void)ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    const char* filename = enclave_filename;
    ret = sgx_create_enclave(filename, flags, &token, &updated, peid, NULL);
    if (ret != SGX_SUCCESS) {
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE) {
            CloseHandle(token_handler);
        }
#else
        if (fp != NULL) {
            fclose(fp);
        }
#endif
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE) {
            CloseHandle(token_handler);
        }
        return 0;
    }

    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
    if (write_num != sizeof(sgx_launch_token_t))
    {
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    }
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == NULL)
    {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
    {
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    }
    fclose(fp);
#endif
    return 0;
}

Tcps_StatusCode Tcps_CreateTA(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId)
{
    char tokenFilename[256];
    sprintf_s(tokenFilename, sizeof(tokenFilename), "%s.token", a_TaIdString);

    char enclaveFilename[256];
#if defined(_MSC_VER)
    sprintf_s(enclaveFilename, sizeof(enclaveFilename), "%s.signed.dll", a_TaIdString);
#elif defined(__GNUC__)
    sprintf_s(enclaveFilename, sizeof(enclaveFilename), "%s.signed.so", a_TaIdString);
#endif

    if (query_sgx_status() < 0)
    {
        /* Either SGX is disabled, or a reboot is required to enable SGX. */
        return Tcps_Bad;
    }

    /* Initialize the enclave. */
    if (initialize_enclave(tokenFilename, enclaveFilename, a_Flags, a_pId) < 0)
    {
        return Tcps_Bad;
    }

    /* Proactively initialize sockets so the enclave isn't required to. */
    WSADATA wsaData;
    (void)WSAStartup(0x202, &wsaData);

    return Tcps_Good;
}

Tcps_StatusCode Tcps_DestroyTA(
    _In_ sgx_enclave_id_t a_Id)
{
    WSACleanup();

    sgx_status_t sgxStatus = sgx_destroy_enclave(a_Id);
    return (sgxStatus == SGX_SUCCESS) ? Tcps_Good : Tcps_Bad;
}
