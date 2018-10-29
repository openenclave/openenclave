# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
include $(TCPS_SDK_ROOT_PATH)tcps_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

../helloworld_t.c: ../../helloworld.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../helloworld.edl

../helloworld_t.h: ../../helloworld.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../helloworld.edl

# Add the c file generated from your EDL file here
srcs-y             += ../helloworld_t.c

# Add additional sources here
srcs-y             += ../enc.c

# Add additional libraries here
# libnames         += ...
# libdirs          += ...
# libdeps          += ...
