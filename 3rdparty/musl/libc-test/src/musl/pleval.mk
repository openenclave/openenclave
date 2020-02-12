# suppress warnings, with gcc -Wno-parentheses -Wno-bool-compare is needed
$(N).CFLAGS := -w
# do not build and run the dynamic link tests (__pleval is no longer public)
$(B)/$(N).err:
	touch $@
