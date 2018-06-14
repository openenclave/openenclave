# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

ifndef OPENENCLAVE_CONFIG

# If no config is specified, use the config from parent folder.
OPENENCLAVE_CONFIG=$(shell pwd)/../config.mak

# Export the variable so that it is visible inside sample makefiles.
# Note: Variables defined in command line are automatically exported.
export OPENENCLAVE_CONFIG

endif

.PHONY: run

define NEWLINE


endef

# Obtain list of installed samples.
DIRS = $(wildcard */)

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

run-silent:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NEWLINE) )

run:
	$(MAKE) -s run-silent

world: clean build run
