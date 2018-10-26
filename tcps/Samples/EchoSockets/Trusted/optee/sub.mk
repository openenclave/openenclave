include $(TCPS_SDK_ROOT_PATH)tcps_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

../SampleTA_t.c: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../SampleTA.edl

../SampleTA_t.h: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" ../../SampleTA.edl

../TcpsCalls_t.c: $(TCPS_SDK_ROOT_PATH)Inc/TcpsCalls.edl
	$(SGX_EDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" $(TCPS_SDK_ROOT_PATH)Inc/TcpsCalls.edl

../TcpsCalls_t.h: $(TCPS_SDK_ROOT_PATH)Inc/TcpsCalls.edl
	$(SGX_EDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(SGX_PATHSEP)$(TCPS_SDK_ROOT_PATH)$(SGX_RELATIVE_PATH)include" $(TCPS_SDK_ROOT_PATH)Inc/TcpsCalls.edl

# Add the c file generated from your EDL file here
srcs-y             += ../SampleTA_t.c
srcs-y             += ../TcpsCalls_t.c

# Add additional sources here
srcs-y             += ../SampleTA.c

# Add additional libraries here
# libnames         += ...
# libdirs          += ...
# libdeps          += ...
