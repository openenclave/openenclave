include $(TCPS_SDK_ROOT_PATH)tcps_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

SampleTA_t.c: ../../SampleTA.edl
	$(SGX_EDGER8R) --trusted --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(SGX_PATH)include" ../../SampleTA.edl

SampleTA_t.h: ../../SampleTA.edl
	$(SGX_EDGER8R) --trusted --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(SGX_PATH)include" ../../SampleTA.edl

# Add the c file generated from your EDL file here
srcs-y             += SampleTA_t.c

# Add additional sources here
srcs-y             += ../SampleTA.c

# Add additional libraries here
# libnames         += ...
# libdirs          += ...
# libdeps          += ...
