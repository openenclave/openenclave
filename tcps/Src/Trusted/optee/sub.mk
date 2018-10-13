include ../../../tcps_sub.mk

# Workaround for TcpsCalls_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0

ROOT_RELATIVE_PATH = ../../../

../TcpsCalls_t.c: ../../../Inc/TcpsCalls.edl
	$(SGX_EDGER8R) --trusted --search-path "../../../Inc$(SGX_PATHSEP)$(SGX_PATH)include" --trusted-dir ".."  ../../../Inc/TcpsCalls.edl

../TcpsCalls_t.h: ../../../Inc/TcpsCalls.edl
	$(SGX_EDGER8R) --trusted --search-path "../../../Inc$(SGX_PATHSEP)$(SGX_PATH)include" --trusted-dir ".."  ../../../Inc/TcpsCalls.edl

CFLAGS += -DTRUSTED_CODE -DUSE_OPTEE

global-incdirs-y += ..
global-incdirs-y += ../..
global-incdirs-y += ../../../Inc/optee/Trusted
global-incdirs-y += ../../../Inc/optee
global-incdirs-y += ../../../Inc
global-incdirs-y += $(ROOT_RELATIVE_PATH)External/optee_os/lib/libutee/include
global-incdirs-y += $(ROOT_RELATIVE_PATH)External/RIoT/CyReP/cyrep
global-incdirs-y += $(ROOT_RELATIVE_PATH)External/RIoT/External/tinycbor/src
global-incdirs-y += $(ROOT_RELATIVE_PATH)External/openenclave/include

srcs-y += ../TcpsCalls_t.c
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
srcs-y += cyrep-optee.c
srcs-y += except-optee.c
srcs-y += files-optee.c
srcs-y += rand_optee.c
srcs-y += report-optee.c
srcs-y += strings-optee.c
srcs-y += time-optee.c
srcs-y += trpc-optee.c
