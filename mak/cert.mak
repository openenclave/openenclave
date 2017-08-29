.PHONY: cert

ifndef CERTPRIVATE
$(error "please define CERTPRIVATE")
endif

ifndef CERTPUBLIC
$(error "please define CERTPUBLIC")
endif

cert: $(CERTPRIVATE) $(CERTPUBLIC)

$(CERTPRIVATE):
	openssl genrsa -out $(CERTPRIVATE) -3 3072

$(CERTPUBLIC):
	openssl rsa -in $(CERTPRIVATE) -pubout -out $(CERTPUBLIC)

