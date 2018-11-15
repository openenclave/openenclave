include $(NEW_PLATFORMS_PATH)oe_sub.mk

global-incdirs-y += $(NEW_PLATFORMS_PATH)Inc
global-incdirs-y += optee

# Add any additional include directories here
#global-incdirs-y += ...

../SampleTA_t.c: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(NEW_PLATFORMS_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../SampleTA.edl

../SampleTA_t.h: ../../SampleTA.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(NEW_PLATFORMS_PATH)Inc$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" ../../SampleTA.edl

# Add the c file generated from your EDL file here
srcs-y             += ../SampleTA_t.c

# Add additional sources here
srcs-y             += ../SampleTA.c

# Add additional libraries here
libdirs            += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms

libnames           += oesocket_enc
libdeps            += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms/liboesocket_enc.a

libnames           += oestdio_enc
libdeps            += $(NEW_PLATFORMS_PATH)bin/optee/new_platforms/liboestdio_enc.a
