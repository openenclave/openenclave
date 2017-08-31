.PHONY: cert

ifdef GENTRUSTED
__GENFLAGS=--trusted
endif

ifdef GENUNTRUSTED
__GENFLAGS=--untrusted
endif

ifndef __GENFLAGS
$(error "Please define GENTRUSTED or GENUNTRUSTED")
endif

ifndef GENIDL
$(error "Please define GENIDL")
endif

ifndef GENHDR
   $(error "Please define GENHDR")
endif

ifndef GENSRC
   $(error "Please define GENSRC")
endif

gen: $(GENSRC)

$(GENSRC): $(GENIDL)
	$(BINDIR)/oegen $(__GENFLAGS) $(GENIDL)
