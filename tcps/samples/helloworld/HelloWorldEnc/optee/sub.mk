# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
include $(TCPS_SDK_ROOT_PATH)oe_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

../helloworld_t.c: ../../helloworld.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../helloworld.edl

../helloworld_t.h: ../../helloworld.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../helloworld.edl

# Add the c file generated from your EDL file here
srcs-y             += ../helloworld_t.c

# Add additional sources here
srcs-y             += ../enc.c

# Add additional libraries here
libdirs            += $(TCPS_SDK_ROOT_PATH)bin/optee/tcps
libnames           += oestdio_enc
libdeps            += $(TCPS_SDK_ROOT_PATH)bin/optee/tcps/liboestdio_enc.a
#
# libnames         += ...
# libdirs          += ...
# libdeps          += ...
