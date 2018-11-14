include $(TCPS_SDK_ROOT_PATH)oe_sub.mk

global-incdirs-y += $(TCPS_SDK_ROOT_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

../SampleTA_t.c: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../SampleTA.edl

../SampleTA_t.h: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(TCPS_SDK_ROOT_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../SampleTA.edl

# Add the c file generated from your EDL file here
srcs-y             += ../SampleTA_t.c

# Add additional sources here
srcs-y             += ../SampleTA.c

# Add additional libraries here
libdirs            += $(TCPS_SDK_ROOT_PATH)bin/optee/tcps

libnames           += oesocket_enc
libdeps            += $(TCPS_SDK_ROOT_PATH)bin/optee/tcps/liboesocket_enc.a

libnames           += oestdio_enc
libdeps            += $(TCPS_SDK_ROOT_PATH)bin/optee/tcps/liboestdio_enc.a
