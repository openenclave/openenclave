include ../../../tcps_sub.mk

# Workaround for oeoverintelsgx_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0

ROOT_RELATIVE_PATH = ../../../

../oeoverintelsgx_t.c: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

../oeoverintelsgx_t.h: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

../socket_t.h: $(OE_SDK_ROOT_PATH)include/openenclave/socket.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  $(OE_SDK_ROOT_PATH)include/openenclave/socket.edl

../tcps_socket_t.c: ../socket_t.h

CFLAGS += -DTRUSTED_CODE -DUSE_OPTEE

global-incdirs-y += ..
global-incdirs-y += ../..
global-incdirs-y += ../../../include/optee/Trusted
global-incdirs-y += ../../../include/optee
global-incdirs-y += ../../../include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(OE_SDK_ROOT_PATH)include

srcs-y += ../oeoverintelsgx_t.c
srcs-y += ../../buffer.c
srcs-y += ../CallbackHelper.c
srcs-y += ../cborhelper.c
srcs-y += ../Io.c
srcs-y += ../keygen.c
srcs-y += ../../oeresult.c
srcs-y += ../../oeshim-common.c
srcs-y += ../oeshim_t.c
srcs-y += ../TcpsLogApp.c
srcs-y += ../TcpsLogOcallFile.c
srcs-y += ../tcps_socket_t.c
srcs-y += ../tcps_stdio_t.c
srcs-y += ../tcps_string_t.c

srcs-y += ctype-optee.c
srcs-y += cyres-optee.c
srcs-y += except-optee.c
srcs-y += files-optee.c
srcs-y += keygen-optee.c
srcs-y += rand_optee.c
srcs-y += report-optee.c
srcs-y += strings-optee.c
srcs-y += time-optee.c
srcs-y += trpc-optee.c
srcs-y += helper-optee.c
