# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS +=                                  \
	-I$(O)                                 \
	-I..                                   \
	-I../..                                \
	-I$(NP_INC)/optee/enclave              \
	-I$(NP_INC)/optee                      \
	-I$(NP_INC)                            \
	-I$(CYREP_PATH)/cyrep                  \
	-I$(CYREP_PATH)/tcps                   \
	-I$(TINYCBOR_PATH)/src                 \
	-I$(MBEDTLS_PATH)/include              \
	-I$(OE_INC)

CFLAGS += -DLINUX -DOE_USE_OPTEE -D__OPTEE__

srcs-y += $(GEN)

srcs-y += ../CallbackHelper.c
srcs-y += ../cborhelper.c
srcs-y += ../files_enc.c
srcs-y += ../keygen.c
srcs-y += ../oeshim_enc.c
srcs-y += ../logapp.c
srcs-y += ../log_ocall_file.c
srcs-y += ../socket_enc.c
srcs-y += ../string_t.c
srcs-y += ../../optee_common.c

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

srcs-y += $(CYREP_PATH)/tcps/TcpsId.c

srcs-y += $(TINYCBOR_PATH)/src/cborencoder.c
srcs-y += $(TINYCBOR_PATH)/src/cborparser.c

srcs-y += $(CYREP_PATH)/RiotAes128.c
srcs-y += $(CYREP_PATH)/RiotBase64.c
srcs-y += $(CYREP_PATH)/RiotCrypt.c
srcs-y += $(CYREP_PATH)/RiotDerEnc.c
srcs-y += $(CYREP_PATH)/RiotEcc.c
srcs-y += $(CYREP_PATH)/RiotHmac.c
srcs-y += $(CYREP_PATH)/RiotKdf.c
srcs-y += $(CYREP_PATH)/RiotSha256.c

cflags-$(CYREP_PATH)/RiotAes128.c-y := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotBase64.c-y := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotCrypt.c-y  := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotDerEnc.c-y := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotEcc.c-y    := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotHmac.c-y   := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotKdf.c-y    := -Wno-implicit-function-declaration
cflags-$(CYREP_PATH)/RiotSha256.c-y := -Wno-implicit-function-declaration
