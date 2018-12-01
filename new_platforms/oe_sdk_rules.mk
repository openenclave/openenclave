export NEW_PLATFORMS_OPTEE_BIN_PATH = $(NEW_PLATFORMS_PATH)/bin/optee
export OE_TRUSTED_LIB_NAME          = oeenclave
export OE_TRUSTED_OUTPUT_PATH       = $(NEW_PLATFORMS_OPTEE_BIN_PATH)/new_platforms
export OE_TRUSTED_LIB_PATH          = $(OE_TRUSTED_OUTPUT_PATH)/lib$(OE_TRUSTED_LIB_NAME).a
export CYREP_CYREP_PATH             = $(OE_SDK_ROOT_PATH)/3rdparty/RIoT/CyReP/cyrep

# Workaround warning treated as error for generated file
# *_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0
