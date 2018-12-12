../socket_insecure_enc.c: $(O)/socket_t.h

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += -I$(O) -I$(OE_INC) -I$(NP_INC)

CFLAGS += -DOE_USE_OPTEE

srcs-y += ../socket_insecure_enc.c
srcs-y += $(GEN)
