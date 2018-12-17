# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += -I$(O) -I$(OE_INC) -I$(NP_INC)

CFLAGS += -DOE_USE_OPTEE

srcs-y += ../socket_insecure_enc.c
srcs-y += $(GEN)
