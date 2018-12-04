include ../../../oe_sub.mk

ROOT_RELATIVE_PATH = ../../../

../socket_t.h: $(OE_SDK_ROOT_PATH)include/openenclave/socket.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  $(OE_SDK_ROOT_PATH)include/openenclave/socket.edl

../socket_insecure_enc.c: ../socket_t.h

CFLAGS += -DOE_USE_OPTEE

global-incdirs-y += $(ROOT_RELATIVE_PATH)include/optee/enclave
global-incdirs-y += $(ROOT_RELATIVE_PATH)include/optee
global-incdirs-y += $(ROOT_RELATIVE_PATH)include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(ROOT_RELATIVE_PATH)../include
global-incdirs-y += ..

srcs-y += ../socket_insecure_enc.c
