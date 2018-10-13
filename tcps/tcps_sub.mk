CFLAGS += -DTRUSTED_CODE -DUSE_OPTEE

export SGXSDKInstallPath=$(TCPS_SDK_ROOT_PATH)/External/SGXSDK
export CYREP_CYREP_PATH=$(TCPS_SDK_ROOT_PATH)/External/RIoT/CyReP/cyrep

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)/Inc/optee/Trusted
global-incdirs-y += $(TCPS_SDK_ROOT_PATH)/Inc/optee
global-incdirs-y += $(TCPS_SDK_ROOT_PATH)/Inc
global-incdirs-y += $(TCPS_SDK_ROOT_PATH)/External/openenclave/include
global-incdirs-y += $(CYREP_CYREP_PATH)
global-incdirs-y += $(SGXSDKInstallPath)/include
global-incdirs-y += $(SGXSDKInstallPath)

libnames    += $(TCPS_TRUSTED_LIB_NAME)
libdirs     += $(TCPS_TRUSTED_OUTPUT_PATH)
libdeps     += $(TCPS_TRUSTED_LIB_PATH)
