CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += -I$(O) -I$(OE_INC) -I$(NP_INC)
CFLAGS += -I../

CFLAGS += -DOE_USE_OPTEE

srcs-y += ../stdio_enc.c
srcs-y += files_optee.c
srcs-y += $(GEN)
