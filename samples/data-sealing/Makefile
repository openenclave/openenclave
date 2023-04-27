# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

.PHONY: all build clean run

OE_CRYPTO_LIB?= mbedtls

# This selects seal plug-ins to be linked into an enclave
OE_SEAL_PLUGINS?= gcmaes

#
# Seal plug-ins are located in BUILD_TYPE specific locations.
# This Makefile searches plug-ins in the following order.
#
OE_SDK_BUILD_TYPES?= Release RelWithDebInfo MinSizeRel Debug

EDL:= datasealing

define oe-config
$(or $(shell pkg-config oe$(strip $1)),	\
	$(error Have you sourced 'openenclaverc'?))
endef

ENCLAVE_CFLAGS:= $(shell pkg-config oeenclave-$(C_COMPILER) --variable=${OE_CRYPTO_LIB}flags)
ENCLAVE_CFLAGS+= $(call oe-config,enclave-$(C_COMPILER) --cflags)
ENCLAVE_CXXFLAGS:= $(shell pkg-config oeenclave-$(CXX_COMPILER) --variable=${OE_CRYPTO_LIB}flags)
ENCLAVE_CXXFLAGS+= $(call oe-config,enclave-$(CXX_COMPILER) --cflags)
ENCLAVE_LDFLAGS:= $(call oe-config,enclave-$(C_COMPILER) --libs)
ENCLAVE_LDFLAGS+= $(call oe-config,enclave-$(C_COMPILER) --variable=$(OE_CRYPTO_LIB)libs)

HOST_CFLAGS:= $(call oe-config,host-$(C_COMPILER) --cflags)
HOST_CXXFLAGS:= $(call oe-config,host-$(CXX_COMPILER) --cflags)
HOST_LDFLAGS:= $(call oe-config,host-$(C_COMPILER) --libs)

INCDIR:= $(call oe-config,enclave-$(CXX_COMPILER) --variable=includedir)
LIBDIR:= $(call oe-config,enclave-$(C_COMPILER) --variable=libdir)/openenclave

#
# Seal plug-ins are searched in two steps.
#

# Step 1 - Determine BUILD_TYPE (hence the directory containing seal plug-ins)
SEAL_PLUGIN_DIR:= $(or $(firstword $(wildcard $(addsuffix /,	\
	$(addprefix $(LIBDIR)/enclave/objects-,$(OE_SDK_BUILD_TYPES))))),	\
	$(error Cannot determine CMAKE_BUILD_TYPE. Object paths:	\
		$(shell find $(LIBDIR)/enclave -type d -name objects-*)))

# Step 2 - Locate seal plug-in object files.
SEAL_PLUGINS:= $(foreach p,$(OE_SEAL_PLUGINS),$(or	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p/*.o),	\
	$(wildcard $(SEAL_PLUGIN_DIR)oeseal_$p-lvi-cfg/*.o),	\
	$(error Seal plug-in \'$p\' missing in $(SEAL_PLUGIN_DIR))))

EDL_OUT_T:= $(addprefix common/$(EDL),_t.c _t.h _args.h)
EDL_OUT_U:= $(addprefix host/$(EDL),_u.c _u.h _args.h)

HEADERS:= $(wildcard *.h */*.h)
ENCLAVES:= $(addsuffix /enclave.signed,enclave_a_v1 enclave_a_v2 enclave_b)
HOST:= host/host

all: build

%/enclave.signed: %/enclave %/data-sealing.conf
	oesign sign -e $< -c $(filter %.conf,$^) -k $(filter %.pem,$^)

$(foreach v,a b,$(eval $(filter enclave_$v%,$(ENCLAVES)): private_$v.pem))

%/enclave: %/ecalls.cpp.o common/dispatcher.cpp.o	\
	$(addsuffix .o,$(filter-out %.h,$(EDL_OUT_T))) $(SEAL_PLUGINS)
	$(CC) -o $@ $^ $($(ENCLAVE_OR_HOST)_LDFLAGS)

%/enclave: ENCLAVE_OR_HOST:= ENCLAVE

%.cpp.o: %.cpp $(ENC_HDRS) $(EDL_OUT_T) $(EDL_OUT_U)
	$(CC) $($(ENCLAVE_OR_HOST)_CXXFLAGS) -I. -std=c++11 -Wall -Wextra -Wconversion -Werror -c $< -o $@

%.c.o: %.c $(ENC_HDRS) $(EDL_OUT_T) $(EDL_OUT_U)
	$(CC) $($(ENCLAVE_OR_HOST)_CFLAGS) -I. -c $< -o $@

%.pem:
	openssl genrsa -out $@ -3 3072

$(EDL_OUT_T) $(EDL_OUT_U): $(EDL).edl
	oeedger8r $<	\
		--trusted-dir $(sort $(dir $(EDL_OUT_T)))	\
		--untrusted-dir $(sort $(dir $(EDL_OUT_U)))	\
		--search-path $(INCDIR) --search-path $(INCDIR)/openenclave/edl/sgx

HOST_OBJS:= $(addsuffix .o,	\
	$(wildcard $(dir $(HOST))*.cpp)	\
	$(filter-out %.h,$(EDL_OUT_U)))

$(HOST): $(HOST_OBJS)
	$(CC) -o $@ $^ $($(ENCLAVE_OR_HOST)_LDFLAGS) -lstdc++

$(HOST): ENCLAVE_OR_HOST:= HOST

.INTERMEDIATE: $(basename $(ENCLAVES)) $(HOST_OBJS)

build: $(ENCLAVES) $(HOST)

run: build
	$(HOST) $(ENCLAVES)

clean:
	-rm -f *.pem $(ENCLAVES) $(HOST) $(EDL_OUT_T) $(EDL_OUT_U)
