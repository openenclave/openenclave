export TA_DEV_KIT_DIR            = $(TCPS_SDK_ROOT_PATH)/External/optee_os/out/arm-plat-imx/export-ta_arm32
export TCPS_SDK_OPTEE_BIN_PATH   = $(TCPS_SDK_ROOT_PATH)/bin/optee
export TCPS_TRUSTED_LIB_NAME     = tcps_t
export TCPS_TRUSTED_OUTPUT_PATH  = $(TCPS_SDK_OPTEE_BIN_PATH)/tcps
export TCPS_TRUSTED_LIB_PATH     = $(TCPS_TRUSTED_OUTPUT_PATH)/lib$(TCPS_TRUSTED_LIB_NAME).a
export CYREP_CYREP_PATH          = $(TCPS_SDK_ROOT_PATH)/External/RIoT/CyReP/cyrep
export SGXSDKInstallPath         = $(TCPS_SDK_ROOT_PATH)/External/SGXSDK

# make command line parameters used when building OPTEE TA code
export TA_PARAMETERS = \
    CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- \
    TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

# Workaround warning treated as error for generated file
# *_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0
