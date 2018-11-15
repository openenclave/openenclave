# Copyright (c) Microsoft Corporation.  All Rights Reserved.
# Licensed under the MIT License.
MKDIR = mkdir -p

OE_SDK_ROOT_PATH         = ../../../../
TCPS_OPTEE_BIN_PATH      = $(OE_SDK_ROOT_PATH)new_platforms/bin/optee
OE_TRUSTED_LIB_NAME      = oestdio_enc
OE_TRUSTED_OUTPUT_PATH   = $(TCPS_OPTEE_BIN_PATH)/new_platforms
OE_TRUSTED_LIB_PATH      = $(OE_TRUSTED_OUTPUT_PATH)/lib$(OE_TRUSTED_LIB_NAME).a

WARNS = 1
CFG_TEE_TA_LOG_LEVEL=4
CFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) $(EXTRA_CFLAGS)
LIBNAME = $(OE_TRUSTED_OUTPUT_PATH)/lib$(OE_TRUSTED_LIB_NAME)

O := $(OE_TRUSTED_OUTPUT_PATH)/optee

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean1: clean_output_dir

.PHONY: clean_output_dir
clean_output_dir:
	rm -f -r -v $(OE_TRUSTED_OUTPUT_PATH)
