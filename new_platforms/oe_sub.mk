CFLAGS += -DOE_USE_OPTEE

export NEW_PLATFORMS_PATH=$(OE_SDK_ROOT_PATH)new_platforms/
export RIoTDir=$(OE_SDK_ROOT_PATH)3rdparty/RIoT/
export OpteeDir=$(OE_SDK_ROOT_PATH)3rdparty/optee_os/
export CYREP_CYREP_PATH=$(RIoTDir)CyReP/cyrep
export OE_EDL_PATH=$(OE_SDK_ROOT_PATH)include/openenclave

global-incdirs-y += $(NEW_PLATFORMS_PATH)include/optee/enclave
global-incdirs-y += $(NEW_PLATFORMS_PATH)include/optee
global-incdirs-y += $(NEW_PLATFORMS_PATH)include
global-incdirs-y += $(OE_SDK_ROOT_PATH)include
global-incdirs-y += $(CYREP_CYREP_PATH)

libnames    += $(OE_TRUSTED_LIB_NAME)
libdirs     += $(OE_TRUSTED_OUTPUT_PATH)
libdeps     += $(OE_TRUSTED_LIB_PATH)
