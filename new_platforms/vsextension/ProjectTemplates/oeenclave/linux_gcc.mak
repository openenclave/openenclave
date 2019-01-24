# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Name of the binary, not including the extension.  OP-TEE TA's must be a GUID.
BINARY=$guid1$

# Path to the TA Dev Kit.
TA_DEV_KIT_DIR=$OETADevKitPath$

# Where to place the compiled binaries.
O := ../../bin/ARM/optee

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
