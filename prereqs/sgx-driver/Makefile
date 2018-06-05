# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: getdist build

getdist:
	$(MAKE) get-dependencies
	$(MAKE) clone-sources

distclean:
	- rm -rf sgx-driver

build:
	$(MAKE) -C sgx-driver sign

clean:
	$(MAKE) -C sgx-driver clean

install:
	$(MAKE) -s uninstall
	$(MAKE) copy-module
	$(MAKE) update-modules
	$(MAKE) update-devrules
	$(MAKE) load-module
	$(MAKE) check-running

uninstall:
	$(MAKE) unload-module
	$(MAKE) remove-module

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

UNAME_R=$(shell uname -r)

LINUX_HEADERS=linux-headers-$(UNAME_R)

MODULE=$(wildcard ./sgx-driver/intel_sgx.ko)

DIR=/lib/modules/$(UNAME_R)/kernel/drivers/intel/sgx

DEV=$(wildcard /dev/sgx)

RUNNING=$(shell lsmod | grep intel_sgx)

get-dependencies:
	apt-get install $(LINUX_HEADERS) libssl-dev

# Workaround until https://github.com/otcshare/NextGenSGXAttestationLibs.git
# is made public and can be directly git-cloned
clone-sources:
	-@ rm -f sgx-driver.tgz
	@ wget http://10.224.140.70:8888/sgx-driver.tgz
	@ tar -zxvf sgx-driver.tgz --overwrite
	-@ rm -f sgx-driver.tgz

copy-module:
ifeq ($(MODULE),)
	@ echo "*** Module not found: $(MODULE)"
	@ exit 1
endif
ifneq ($(DEV),)
	@ echo "*** Device already exists: {$(DEV)}"
	@ exit 1
endif
	mkdir -p $(DIR)
	cp $(MODULE) $(DIR)

update-modules:
	(cat /etc/modules | grep -Fxq intel_sgx || echo intel_sgx >> /etc/modules)

update-devrules:
	(echo 'SUBSYSTEM=="sgx",KERNEL=="sgx",RUN+="/bin/chmod 666 /dev/$$name"' | sudo tee /etc/udev/rules.d/10-sgx.rules)

load-module:
	/sbin/depmod
	/sbin/modprobe intel_sgx

check-running:
ifeq ($(RUNNING),)
	@ echo "*** Failed to start driver: intel_sgx not found by lsmod"
	@ exit 1
endif
ifeq ($(DEV),)
	@ echo "*** Failed to start driver: /dev/sgx does not exist"
	@ exit 1
endif

unload-module:
	- /sbin/modprobe -r intel_sgx 2> /dev/null > /dev/null

remove-module:
	- rm -rf $(DIR)
	- /sbin/depmod
	- /bin/sed -i '/^intel_sgx$$/d' /etc/modules

