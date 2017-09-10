include ../../mak/defs.mak

all:
	doxygen doxygen.conf
	$(MAKE) -C md

clean:
	rm -rf html latex xml

distclean:

depend:

browse:
	firefox html/index.html

push:
	( cd ../md; git add *.md )
	( cd ../md; git commit -m "update doxygen documentation" . )
	( cd ../md; git push )

