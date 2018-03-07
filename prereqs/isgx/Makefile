# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: linux-sgx-driver build

build:
	$(MAKE) -C linux-sgx-driver

linux-sgx-driver:
	git clone https://github.com/01org/linux-sgx-driver

clean:
	$(MAKE) -C linux-sgx-driver clean

distclean:
	rm -rf linux-sgx-driver

##==============================================================================
##
## install:
##
##==============================================================================

MODULE=$(wildcard ./linux-sgx-driver/isgx.ko)

UNAME_R=$(shell uname -r)

DIR=/lib/modules/$(UNAME_R)/kernel/drivers/intel/sgx

DEV=$(wildcard /dev/isgx)

RUNNING=$(shell lsmod | grep isgx)

install:
	$(MAKE) -s stop-aesm
	$(MAKE) -s run-rmmod
	$(MAKE) mkdir
	$(MAKE) check-module
	$(MAKE) check-device
	$(MAKE) copy-module
	$(MAKE) update-modules
	$(MAKE) run-depmod
	$(MAKE) run-modprobe
	$(MAKE) check-running
	$(MAKE) -s start-aesm

stop-aesm:
	-@ service aesmd stop 2> /dev/null > /dev/null

start-aesm:
	-@ service aesmd start 2> /dev/null > /dev/null

run-rmmod:
	-@ /sbin/rmmod isgx 2> /dev/null > /dev/null

mkdir:
	mkdir -p $(DIR)

check-module:
ifeq ($(MODULE),)
	@ echo "*** Module not found: $(MODULE)"
	@ exit 1
endif

check-device:
ifneq ($(DEV),)
	@ echo "*** Device already exists: {$(DEV)}"
	@ exit 1
endif

copy-module:
	cp $(MODULE) $(DIR)

update-modules:
	( cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules )

run-depmod:
	/sbin/depmod

run-modprobe:
	/sbin/modprobe isgx

check-running:
ifeq ($(RUNNING),)
	@ echo "*** Failed to start driver: isgx not found by lsmod"
	@ exit 1
endif
ifeq ($(DEV),)
	@ echo "*** Failed to start driver: /dev/isgx does not exist"
	@ exit 1
endif

##==============================================================================
##
## uninstall:
##
##==============================================================================

uninstall:
	$(MAKE) -s stop-aesm
	$(MAKE) -s run-rmmod

