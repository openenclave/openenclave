# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include $(NEW_PLATFORMS_PATH)oe_sub.mk

global-incdirs-y += $(NEW_PLATFORMS_PATH)include
global-incdirs-y += optee

# Add any additional include directories here
global-incdirs-y += $(OE_SDK_ROOT_PATH)include

../oetests_t.c: ../../oetests.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(NEW_PLATFORMS_PATH)include$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../oetests.edl

../oetests_t.h: ../../oetests.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(NEW_PLATFORMS_PATH)include$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../oetests.edl

# Add the c file generated from your EDL file here
srcs-y             += ../oetests_t.c

# Add additional sources here
srcs-y             += ../OETestTA.c
srcs-y             += ../oetests_enclave.c

# Add additional libraries here
libdirs          += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms

libnames         += oesocket_enc
libdeps          += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms/liboesocket_enc.a

libnames         += oestdio_enc
libdeps          += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms/liboestdio_enc.a
