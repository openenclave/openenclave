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
all: optee-client gtest usdk oesocket_host oestdio_host usdk-tests tsdk oesocket_enc oestdio_enc tsdk-tests

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
	make -C ../libsocket/host/linux

.PHONY: oestdio_host
oestdio_host: usdk
	make -C ../libstdio/host/linux

.PHONY: usdk-tests
usdk-tests: gtest usdk oesocket_host oestdio_host
	make -C tests/oetests_host
	
# Trusted SDK
# -----------

.PHONY: tsdk
tsdk:
	SGX_RELATIVE_PATH=../3rdparty/SGXSDK/ SGX_PATHSEP=: SGX_EDGER8R=$(shell which sgx_edger8r) OEPATHSEP=: CROSS_COMPILE=$(TRUSTED_CROSS_COMPILE) make -C src/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: oesocket_enc
oesocket_enc: tsdk
	SGX_RELATIVE_PATH=../3rdparty/SGXSDK/ SGX_PATHSEP=: SGX_EDGER8R=$(shell which sgx_edger8r) OEPATHSEP=: CROSS_COMPILE=$(TRUSTED_CROSS_COMPILE) make -C ../libsocket/enc/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: oestdio_enc
oestdio_enc: tsdk
	SGX_RELATIVE_PATH=../3rdparty/SGXSDK/ SGX_PATHSEP=: SGX_EDGER8R=$(shell which sgx_edger8r) OEPATHSEP=: CROSS_COMPILE=$(TRUSTED_CROSS_COMPILE) make -C ../libstdio/enc/optee -f linux_gcc.mak BUILD_TARGET=debug

.PHONY: tsdk-tests
tsdk-tests: tsdk oesocket_enc oestdio_enc
	SGX_RELATIVE_PATH=../3rdparty/SGXSDK/ SGX_PATHSEP=: SGX_EDGER8R=$(shell which sgx_edger8r) OEPATHSEP=: CROSS_COMPILE=$(TRUSTED_CROSS_COMPILE) make -C tests/oetests_enclave/optee -f linux_gcc.mak BUILD_TARGET=debug

# Clean Targets
# -------------

.PHONY: clean
clean: optee-client-clean gtest-clean usdk-clean oesocket_host-clean oestdio_host-clean usdk-tests-clean tsdk-clean oesocket_enc-clean oestdio_enc-clean tsdk-tests-clean

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
	make -C ../libsocket/host/linux clean

.PHONY: oestdio_host-clean
oestdio_host-clean:
	make -C ../libstdio/host/linux clean

.PHONY: usdk-tests-clean
usdk-tests-clean:
	make -C tests/oetests_host clean

.PHONY: tsdk-clean
tsdk-clean:
	make -C src/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: oesocket_enc-clean
oesocket_enc-clean:
	make -C ../libsocket/enc/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: oestdio_enc-clean
oestdio_enc-clean:
	make -C ../libstdio/enc/optee -f linux_gcc.mak BUILD_TARGET=debug clean

.PHONY: tsdk-tests-clean
tsdk-tests-clean:
	make -C tests/oetests_enclave/optee -f linux_gcc.mak BUILD_TARGET=debug clean

