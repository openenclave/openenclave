# Copyright (c) Microsoft Corporation.  All Rights Reserved.
# Licensed under the MIT License.
MKDIR = mkdir -p

TCPS_SDK_ROOT_PATH       = ../../..
TCPS_OPTEE_BIN_PATH      = $(TCPS_SDK_ROOT_PATH)/bin/optee
TCPS_TRUSTED_LIB_NAME    = tcps_t
TCPS_TRUSTED_OUTPUT_PATH = $(TCPS_OPTEE_BIN_PATH)/tcps
TCPS_TRUSTED_LIB_PATH    = $(TCPS_TRUSTED_OUTPUT_PATH)/lib$(TCPS_TRUSTED_LIB_NAME).a

WARNS = 1
CFG_TEE_TA_LOG_LEVEL=4
CFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) $(EXTRA_CFLAGS)
LIBNAME = $(TCPS_TRUSTED_OUTPUT_PATH)/lib$(TCPS_TRUSTED_LIB_NAME)

O := $(TCPS_TRUSTED_OUTPUT_PATH)/optee

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean1: clean_output_dir

.PHONY: clean_output_dir
clean_output_dir:
	rm -f -r -v $(TCPS_TRUSTED_OUTPUT_PATH)
