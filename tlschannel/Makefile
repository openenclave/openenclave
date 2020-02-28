# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all clean

DIRS=gencreds cli srv

define NL


endef

all:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
