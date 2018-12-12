../socket_insecure_enc.c: $(O)/socket_t.h

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += -I$(O) -I$(OE_INC) -I$(NP_INC)

CFLAGS += -DOE_USE_OPTEE
CFLAGS += -D_INC_STRING

srcs-y += ../socket_insecure_enc.c
srcs-y += $(GEN)
