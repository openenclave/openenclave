../stdio_enc.c: ../stdio_t.h
files_optee.c: ../stdio_t.h

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += -I$(O) -I$(OE_INC) -I$(NP_INC) 

CFLAGS += -DOE_USE_OPTEE

srcs-y += ../stdio_enc.c
srcs-y += files_optee.c
srcs-y += $(GEN)
