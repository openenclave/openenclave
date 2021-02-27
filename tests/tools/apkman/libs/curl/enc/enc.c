// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

// For mounting host filesystem
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <sys/mount.h>

#include "test_t.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

void test_curl(CURL* curl, const char* url)
{
    // TODO figure out how to fix the following error:
    //  Problem with the SSL CA cert (path? access rights?)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
    curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    OE_TEST(curl_easy_perform(curl) == CURLE_OK);
}

int main(int argc, char** argv)
{
    CURL* curl = curl_easy_init();

    if (argc >= 2)
    {
        for (int i = 1; i < argc; ++i)
            test_curl(curl, argv[i]);
    }
    else
    {
        // The first website.
        test_curl(curl, "http://info.cern.ch");
    }

    curl_easy_cleanup(curl);
    return 0;
}

// extern void register_pthread_hooks(void);
int enc_main(int argc, char** argv)
{
    int ret = -1;

    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    OE_TEST(oe_load_module_host_epoll() == OE_OK);
    OE_TEST(oe_load_module_host_resolver() == OE_OK);
    // register_pthread_hooks();

    ret = main(argc, (char**)argv);
    oe_umount("/");

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    4);   /* NumTCS */
