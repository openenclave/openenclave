# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: build

enc1/private.pem:
	openssl genrsa -out enc1/private.pem -3 3072

enc1/public.pem: enc1/private.pem
	openssl rsa -in enc1/private.pem -out enc1/public.pem -pubout

enc2/private.pem:
	openssl genrsa -out enc2/private.pem -3 3072

enc2/public.pem: enc2/private.pem
	openssl rsa -in enc2/private.pem -out enc2/public.pem -pubout

# The enclaves in the sample will check if the other enclave is signed
# with the expected key. Since this sample builds both enclaves, we can
# inject the expected public keys at build time.
#
# If the other public key isn't known, then we would have to load the
# public key from the host. We can't simply load the raw public key since
# a malicious host might change it. So, we would need to load a certicate
# that contains the expected public key that is signed by a trusted CA.
common/pubkeys.h: enc1/public.pem enc2/public.pem
	./gen_pubkey_header.sh common/pubkeys.h enc1/public.pem enc2/public.pem

build: common/pubkeys.h
	$(MAKE) -C enc1
	$(MAKE) -C enc2	
	$(MAKE) -C host

clean:
	$(MAKE) -C enc1 clean
	$(MAKE) -C enc2 clean
	$(MAKE) -C host clean

run:
	host/attestation_host ./enc1/enclave1.signed.so ./enc2/enclave2.signed.so
