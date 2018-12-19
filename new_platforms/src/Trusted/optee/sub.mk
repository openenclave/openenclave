include ../../../oe_sub.mk

WARNS=0

ROOT_RELATIVE_PATH = ../../../

../oeinternal_t.c: ../../oeinternal.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  ../../oeinternal.edl

../oeinternal_t.h: ../../oeinternal.edl
	$(OEEDGER8R) --trusted --search-path "../..$(OEPATHSEP)$(OE_SDK_ROOT_PATH)include" --trusted-dir ".."  ../../oeinternal.edl

CFLAGS += -DOE_USE_OPTEE -D__OPTEE__

global-incdirs-y += ..
global-incdirs-y += ../..
global-incdirs-y += ../../../include/optee/enclave
global-incdirs-y += ../../../include/optee
global-incdirs-y += ../../../include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)CyReP/tcps
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(OE_SDK_ROOT_PATH)include
global-incdirs-y += $(OE_SDK_ROOT_PATH)3rdparty/mbedtls/mbedtls/include
global-incdirs-y += $(NEW_PLATFORMS_PATH)src/Trusted

srcs-y += ../oeinternal_t.c
srcs-y += ../CallbackHelper.c
srcs-y += ../cborhelper.c
srcs-y += ../files_enc.c
srcs-y += ../keygen.c
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

srcs-y += $(RIoTDir)CyReP/RiotAes128.c
srcs-y += $(RIoTDir)CyReP/RiotBase64.c
srcs-y += $(RIoTDir)CyReP/RiotCrypt.c
srcs-y += $(RIoTDir)CyReP/RiotDerEnc.c
srcs-y += $(RIoTDir)CyReP/RiotEcc.c
srcs-y += $(RIoTDir)CyReP/RiotHmac.c
srcs-y += $(RIoTDir)CyReP/RiotKdf.c
srcs-y += $(RIoTDir)CyReP/RiotSha256.c

srcs-y += $(RIoTDir)CyReP/tcps/TcpsId.c
srcs-y += $(RIoTDir)External/tinycbor/src/cborencoder.c
srcs-y += $(RIoTDir)External/tinycbor/src/cborparser.c
