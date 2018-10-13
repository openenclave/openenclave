# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
TCPS_SDK_ROOT_PATH = ../../../../

BINARY=aac3129e-c244-4e09-9e61-d4efcf31bca3

include $(TCPS_SDK_ROOT_PATH)/tcps_sdk_rules.mk

CFG_TEE_TA_LOG_LEVEL=4

CFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) $(EXTRA_CFLAGS)

O := $(TCPS_SDK_OPTEE_BIN_PATH)/Samples/EchoSockets

clean1: clean_stripped_file clean_output_dir

.PHONY: clean_stripped_file clean_output_dir

clean_stripped_file:
	rm -f $(BINARY).stripped.elf

clean_output_dir:
	rm -f -r -v $(TCPS_SDK_OPTEE_BIN_PATH)/Sample
