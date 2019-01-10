# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
OE_SDK_ROOT_PATH = ../../../../../
NEW_PLATFORMS_PATH = $(OE_SDK_ROOT_PATH)new_platforms/

BINARY=$guid1$

include $(NEW_PLATFORMS_PATH)/oe_sdk_rules.mk

CFG_TEE_TA_LOG_LEVEL=4

CFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) $(EXTRA_CFLAGS)

O := $(NEW_PLATFORMS_OPTEE_BIN_PATH)/samples/$safeprojectname$

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean1: clean_stripped_file clean_output_dir

.PHONY: clean_stripped_file clean_output_dir

clean_stripped_file:
	rm -f $(BINARY).stripped.elf

clean_output_dir:
	rm -f -r -v $(NEW_PLATFORMS_OPTEE_BIN_PATH)/Sample
