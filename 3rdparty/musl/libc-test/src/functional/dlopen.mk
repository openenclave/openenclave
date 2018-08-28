$(N).BINS:=$(B)/$(N).exe
$(N).LDFLAGS:=-rdynamic
$(B)/$(N).err: $(B)/$(D)/dlopen_dso.so
