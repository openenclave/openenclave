$(N).BINS:=$(B)/$(N).exe
$(N).LDFLAGS:=-Wl,-rpath='$$ORIGIN'
$(B)/$(N).err: $(B)/$(D)/tls_get_new-dtv_dso.so
