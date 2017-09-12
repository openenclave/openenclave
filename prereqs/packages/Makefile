INSTALL = apt-get -y install

all: .packages

.packages:
	$(INSTALL) build-essential
	$(INSTALL) ocaml
	$(INSTALL) automake
	$(INSTALL) autoconf
	$(INSTALL) libtool
	$(INSTALL) wget
	$(INSTALL) python
	$(INSTALL) libssl-dev
	$(INSTALL) libcurl4-openssl-dev
	$(INSTALL) protobuf-compiler
	$(INSTALL) libprotobuf-dev
	$(INSTALL) build-essential
	$(INSTALL) python
	$(INSTALL) libssl-dev
	$(INSTALL) libcurl4-openssl-dev
	$(INSTALL) libprotobuf-dev
	$(INSTALL) uuid-dev
	$(INSTALL) libxml2-dev
	$(INSTALL) cmake
	$(INSTALL) pkg-config
	$(INSTALL) subversion
	$(INSTALL) cloc
	$(INSTALL) libexpat1
	$(INSTALL) libexpat1-dev
	$(INSTALL) ccache
	touch .packages

clean:

distclean:
	rm -f .packages

install:
