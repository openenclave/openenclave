# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include $(TCPS_SDK_ROOT_PATH)tcps_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
global-incdirs-y += $(OE_SDK_ROOT_PATH)include

../TcpsSdkTestTA_t.c: ../../TcpsSdkTestTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../TcpsSdkTestTA.edl

../TcpsSdkTestTA_t.h: ../../TcpsSdkTestTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../TcpsSdkTestTA.edl

# Add the c file generated from your EDL file here
srcs-y             += ../TcpsSdkTestTA_t.c

# Add additional sources here
srcs-y             += ../OETestTA.c
srcs-y             += ../TcpsSdkTestTA.c

# Add additional libraries here
# libnames         += ...
# libdirs          += ...
# libdeps          += ...
