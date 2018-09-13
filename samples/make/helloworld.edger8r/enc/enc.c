// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

// Include the trusted helloworld header that is generated
// during the build. This file is generated by calling the 
// sdk tool oeedger8r against the helloworld.edl file.
#include "helloworld_t.h"

// This is the function that the host calls. It prints
// a message in the enclave before calling back out to
// the host to print a message from there too.
void enclave_helloworld()
{
    // Print a message from the enclave. Note that this
    // does not directly call fprintf, but calls into the
    // host and calls fprintf from there. This is because
    // the fprintf function is not part of the enclave
    // as it requires support from the kernel.
    fprintf(stdout, "Hello world from the enclave\n");

    // Call back into the host
    host_helloworld();
}
