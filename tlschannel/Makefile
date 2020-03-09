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
	rm -f cert.der private_key.pem

run: all creds
	( ./srv/tlssrv & )
	sleep 2
	( ./cli/tlscli cert.der private_key.pem )
	killall tlssrv

cli: creds
	( ./cli/tlscli cert.der private_key.pem )

creds:
	( ./gencreds/gencreds cert.der private_key.pem )
