.PHONY: sign

ifndef SIGNIN
$(error "please define SIGNIN")
endif

ifndef SIGNOUT
$(error "please define SIGNOUT")
endif

ifndef SIGNKEY
$(error "please define SIGNKEY")
endif

ifndef SIGNCONF
$(error "please define SIGNCONF")
endif

sign: $(SIGNOUT)

$(SIGNOUT):
	sgx_sign sign -key $(SIGNKEY) -enclave $(SIGNIN) -out $(SIGNOUT) -config $(SIGNCONF) > /dev/null
	chmod +x $(SIGNOUT)
