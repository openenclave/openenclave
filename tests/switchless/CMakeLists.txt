# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(switchless)
subdirs(host enc)

add_enclave_test(tests/switchless switchless_host switchless_enc)
