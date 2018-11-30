include ../../../oe_sub.mk

# Workaround for oeoverintelsgx_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0

ROOT_RELATIVE_PATH = ../../../

../oeoverintelsgx_t.c: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

../oeoverintelsgx_t.h: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

../oeinternal_t.c: ../../oeinternal.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  ../../oeinternal.edl

../oeinternal_t.h: ../../oeinternal.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  ../../oeinternal.edl

CFLAGS += -DOE_USE_OPTEE

global-incdirs-y += ..
global-incdirs-y += ../..
global-incdirs-y += ../../../include/optee/enclave
global-incdirs-y += ../../../include/optee
global-incdirs-y += ../../../include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(OE_SDK_ROOT_PATH)include

srcs-y += ../oeoverintelsgx_t.c
srcs-y += ../oeinternal_t.c
srcs-y += ../../buffer.c
srcs-y += ../CallbackHelper.c
srcs-y += ../cborhelper.c
srcs-y += ../files_enc.c
srcs-y += ../Io.c
srcs-y += ../keygen.c
srcs-y += ../../oeresult.c
srcs-y += ../../optee_common.c
srcs-y += ../oeshim_enc.c
srcs-y += ../logapp.c
srcs-y += ../log_ocall_file.c
srcs-y += ../socket_enc.c
srcs-y += ../string_t.c

srcs-y += ctype_optee.c
srcs-y += cyres_optee.c
srcs-y += except_optee.c
srcs-y += keygen_optee.c
srcs-y += rand_optee.c
srcs-y += report_optee.c
srcs-y += strings_optee.c
srcs-y += time_optee.c
srcs-y += trpc_optee.c
srcs-y += helper_optee.c
srcs-y += oeresult_optee.c
