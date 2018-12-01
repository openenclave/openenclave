include ../../../oe_sub.mk

ROOT_RELATIVE_PATH = ../../../

../stdio_t.h: $(OE_SDK_ROOT_PATH)include/openenclave/stdio.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  $(OE_SDK_ROOT_PATH)include/openenclave/stdio.edl

../stdio_enc.c: ../stdio_t.h

files_optee.c: ../stdio_t.h

CFLAGS += -DOE_USE_OPTEE

global-incdirs-y += $(ROOT_RELATIVE_PATH)include/optee/enclave
global-incdirs-y += $(ROOT_RELATIVE_PATH)include/optee
global-incdirs-y += $(ROOT_RELATIVE_PATH)include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(ROOT_RELATIVE_PATH)../include
global-incdirs-y += ..

srcs-y += ../stdio_enc.c
srcs-y += files_optee.c
