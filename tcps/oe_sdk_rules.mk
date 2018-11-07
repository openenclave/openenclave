# TA_DEV_KIT_DIR may be overridden if the user wishes to use a version of
# OP-TEE outside of the OE tree.
ifeq ($(TA_DEV_KIT_DIR),)
export TA_DEV_KIT_DIR            = $(OE_SDK_ROOT_PATH)/3rdparty/optee_os/out/arm-plat-imx/export-ta_arm32
endif
export TCPS_SDK_OPTEE_BIN_PATH   = $(TCPS_SDK_ROOT_PATH)/bin/optee
export TCPS_TRUSTED_LIB_NAME     = oeenclave
export TCPS_TRUSTED_OUTPUT_PATH  = $(TCPS_SDK_OPTEE_BIN_PATH)/tcps
export TCPS_TRUSTED_LIB_PATH     = $(TCPS_TRUSTED_OUTPUT_PATH)/lib$(TCPS_TRUSTED_LIB_NAME).a
export CYREP_CYREP_PATH          = $(OE_SDK_ROOT_PATH)/3rdparty/RIoT/CyReP/cyrep
export SGXSDKInstallPath         = $(OE_SDK_ROOT_PATH)/3rdparty/SGXSDK

# make command line parameters used when building OPTEE TA code
export TA_PARAMETERS = \
    CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- \
    TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

# Workaround warning treated as error for generated file
# *_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0
