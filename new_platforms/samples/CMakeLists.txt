# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(helloworld)
add_subdirectory(sockets)

# CyReS attestation is not available on SGX, so this sample is only valid for
# ARM TrustZone.
if(TZ)
    add_subdirectory(localattestation)
    add_subdirectory(oe_policy_tool)
endif()
