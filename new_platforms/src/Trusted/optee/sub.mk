CFLAGS += $(EXTRA_CFLAGS)

CFLAGS +=                                  \
	-I$(O)                                 \
	-I..                                   \
	-I../..                                \
	-I$(NP_INC)/optee/enclave              \
	-I$(NP_INC)/optee                      \
	-I$(NP_INC)                            \
	-I$(OPTEE_OS_PATH)/lib/libutee/include \
	-I$(RIOT_PATH)/CyReP/cyrep             \
	-I$(TINYCBOR_PATH)/src                 \
	-I$(OE_INC)

CFLAGS += -DOE_USE_OPTEE

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

srcs-y += $(GEN)
