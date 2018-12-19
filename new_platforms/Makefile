ifeq ($(ARCH),aarch32)
TRUSTED_CROSS_COMPILE = /usr/bin/arm-linux-gnueabi-
else ifeq ($(ARCH),aarch64)
TRUSTED_CROSS_COMPILE = /usr/bin/aarch64-linux-gnu-
else
$(error ARCH=$(ARCH) - Should be 'aarch32' or 'aarch64')
endif

# Default Target
# --------------

.PHONY: all
all: optee-client  \
     gtest         \
     usdk          \
     oesocket_host \
     oestdio_host  \
     usdk-tests    \
     usdk-samples  \
     tsdk          \
     oesocket_enc  \
     oestdio_enc   \
     tsdk-tests    \
     tsdk-samples

.PHONY: help
help:
	@echo "The following environmental variables must be set:"
	@echo ""
	@echo "\tCROSS_COMPILE"
	@echo "\tTA_DEV_KIT_DIR"
	@echo "\tARCH"
	@echo ""
	@echo "If you built OP-TEE OS separately from this repository,"
	@echo "the three variables above must be in sync with the toolchain"
	@echo "you used and with that build's TA dev kit output."

# External Dependencies
# ---------------------

.PHONY: optee-client
optee-client:
	DEBUG=1 make -C ../3rdparty/optee_client

.PHONY: gtest
gtest:
	make -C tests/gtest

# Untrusted SDK
# -------------

.PHONY: usdk
usdk: optee-client
	make -C src/Untrusted/linux

.PHONY: oesocket_host
oesocket_host: usdk
	make -C libsocket/host/linux

.PHONY: oestdio_host
oestdio_host: usdk
	make -C libstdio/host/linux

.PHONY: usdk-tests
usdk-tests: gtest usdk oesocket_host oestdio_host
	make -C tests/oetests_host

.PHONY: usdk-samples
usdk-samples: usdk oesocket_host oestdio_host
	make -C samples/sockets/host/SampleClientApp
	make -C samples/sockets/host/SampleServerApp
	make -C samples/helloworld/HelloWorldHost
	make -C samples/local_attestation/host

# Trusted SDK
# -----------

TRUSTED_PARAMS=SGX_RELATIVE_PATH=../3rdparty/SGXSDK/ SGX_PATHSEP=: SGX_EDGER8R=$(shell which sgx_edger8r) OEPATHSEP=: CROSS_COMPILE=$(TRUSTED_CROSS_COMPILE)

.PHONY: tsdk
tsdk:
	$(TRUSTED_PARAMS) make -C src/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: oesocket_enc
oesocket_enc: tsdk
	$(TRUSTED_PARAMS) make -C libsocket/enc/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: oestdio_enc
oestdio_enc: tsdk
	$(TRUSTED_PARAMS) make -C libstdio/enc/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: tsdk-tests
tsdk-tests: tsdk oesocket_enc oestdio_enc
	$(TRUSTED_PARAMS) make -C tests/oetests_enclave/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: tsdk-samples
tsdk-samples: tsdk oesocket_enc oestdio_enc
	$(TRUSTED_PARAMS) make -C samples/sockets/enclave/optee -f linux_gcc.mak BUILD_TARGET=debug
	$(TRUSTED_PARAMS) make -C samples/helloworld/HelloWorldEnc/optee -f linux_gcc.mak BUILD_TARGET=debug
	$(TRUSTED_PARAMS) make -C samples/local_attestation/enc/optee -f linux_gcc.mak BUILD_TARGET=debug

# Clean Targets
# -------------

.PHONY: clean
clean: optee-client-clean  \
       gtest-clean         \
       usdk-clean          \
       oesocket_host-clean \
       oestdio_host-clean  \
       usdk-tests-clean    \
       usdk-samples-clean  \
       tsdk-clean          \
       oesocket_enc-clean  \
       oestdio_enc-clean   \
       tsdk-tests-clean    \
       tsdk-samples-clean

.PHONY: optee-client-clean
optee-client-clean:
	make -C ../3rdparty/optee_client clean

.PHONY: gtest-clean
gtest-clean:
	make -C tests/gtest clean

.PHONY: usdk-clean
usdk-clean:
	make -C src/Untrusted/linux clean

.PHONY: oesocket_host-clean
oesocket_host-clean:
	make -C libsocket/host/linux clean

.PHONY: oestdio_host-clean
oestdio_host-clean:
	make -C libstdio/host/linux clean

.PHONY: usdk-tests-clean
usdk-tests-clean:
	make -C tests/oetests_host clean

.PHONY: usdk-samples-clean
usdk-samples-clean:
	make -C samples/sockets/host/SampleClientApp clean
	make -C samples/sockets/host/SampleServerApp clean
	make -C samples/helloworld/HelloWorldHost clean
	make -C samples/local_attestation/host clean

.PHONY: tsdk-clean
tsdk-clean:
	make -C src/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: oesocket_enc-clean
oesocket_enc-clean:
	make -C libsocket/enc/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: oestdio_enc-clean
oestdio_enc-clean:
	make -C libstdio/enc/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: tsdk-tests-clean
tsdk-tests-clean:
	make -C tests/oetests_enclave/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: tsdk-samples-clean
tsdk-samples-clean:
	make -C samples/sockets/enclave/optee -f linux_gcc.mak BUILD_TARGET=debug clean
	make -C samples/helloworld/HelloWorldEnc/optee -f linux_gcc.mak BUILD_TARGET=debug clean
	make -C samples/local_attestation/enc/optee -f linux_gcc.mak BUILD_TARGET=debug clean
