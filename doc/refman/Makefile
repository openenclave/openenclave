include ../../mak/defs.mak

all:
	$(MAKE) -C xml2md
	doxygen doxygen.conf
	$(MAKE) -C md

clean:
	$(MAKE) -C xml2md clean
	rm -rf html latex xml

distclean:

depend:

browse:
	firefox html/index.html

push:
	( cd ../md; git add *.md )
	( cd ../md; git commit -m "update doxygen documentation" . )
	( cd ../md; git push )

