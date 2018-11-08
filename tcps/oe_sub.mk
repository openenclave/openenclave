CFLAGS += -DOE_USE_OPTEE

export TCPS_SDK_ROOT_PATH=$(OE_SDK_ROOT_PATH)tcps/
export RIoTDir=$(OE_SDK_ROOT_PATH)3rdparty/RIoT/
export OpteeDir=$(OE_SDK_ROOT_PATH)3rdparty/optee_os/
export SGXSDKInstallPath=$(OE_SDK_ROOT_PATH)3rdparty/SGXSDK
export CYREP_CYREP_PATH=$(RIoTDir)CyReP/cyrep

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)include/optee/Trusted
global-incdirs-y += $(TCPS_SDK_ROOT_PATH)include/optee
global-incdirs-y += $(TCPS_SDK_ROOT_PATH)include
global-incdirs-y += $(OE_SDK_ROOT_PATH)include
global-incdirs-y += $(CYREP_CYREP_PATH)
global-incdirs-y += $(SGXSDKInstallPath)/include
global-incdirs-y += $(SGXSDKInstallPath)

libnames    += $(TCPS_TRUSTED_LIB_NAME)
libdirs     += $(TCPS_TRUSTED_OUTPUT_PATH)
libdeps     += $(TCPS_TRUSTED_LIB_PATH)
