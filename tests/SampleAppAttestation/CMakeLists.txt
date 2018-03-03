# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(SampleAppAttestation)
add_subdirectory(SampleAppAttestationHost)

add_test(tests/SampleAppAttestation SampleAppAttestationHost/SampleAppAttestationHost ./SampleAppAttestation/SampleAppAttestation.signed.so)
