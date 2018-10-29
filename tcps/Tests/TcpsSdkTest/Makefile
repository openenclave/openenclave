OBJECTS = main.o BufferTest.o TrustedAppTest.o OEEnclaveTest.o OEHostTest.o  SocketsTest.o TcpsSdkTestTA_u.o

EDL_PATH = ../../Src
EDL_INC_PATH = ../../Inc

GTEST_PATH = ../../../3rdparty/googletest/googletest
OE_PATH = ../../../include

DEFINES = -DUNTRUSTED_CODE -DUSE_OPTEE -D_DEBUG -DLINUX
INCLUDES =                        \
    -I../../Inc/optee/Untrusted   \
    -I../../Inc/                  \
    -I../../Inc/linux             \
    -I$(SGX_SDK)/include          \
    -I$(GTEST_PATH)/include       \
    -I$(OE_PATH)

CFLAGS = $(DEFINES) $(INCLUDES) -g
CXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS =                                        \
    -L../gtest                                   \
    -L../../Src/Untrusted/linux                  \
    -L../../../3rdparty/optee_client/out/libteec \
    -l:libgtest.a                                \
    -l:tcps_u.a                                  \
    -l:libteec.a                                 \
    -lpthread

CC = $(CROSS_COMPILE)gcc
CX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar

APP_NAME = TcpsSdkTest

TcpsSdkTest: $(OBJECTS)
	@echo " [LD]\tTcpsSdkTest"
	@$(CX) -o $(APP_NAME) $(OBJECTS) $(LDFLAGS)

TcpsSdkTestTA_u.h TcpsSdkTestTA_u.c: $(EDL_PATH)/TcpsCalls.edl   \
                                     $(EDL_PATH)/TcpsFile.edl    \
                                     $(EDL_PATH)/TcpsSockets.edl
	@echo " [EDGE]\tTcpsSdkTestTA.edl"
	@$(OEEDGER8R) --untrusted --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                        "../TcpsSdkTestTA.edl"

main.o: main.cpp
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

BufferTest.o: BufferTest.cpp TcpsSdkTestTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

TrustedAppTest.o: TrustedAppTest.cpp TcpsSdkTestTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

OEEnclaveTest.o: OEEnclaveTest.cpp TcpsSdkTestTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

OEHostTest.o: OEHostTest.cpp TcpsSdkTestTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

SocketsTest.o: SocketsTest.cpp TcpsSdkTestTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

TcpsSdkTestTA_u.o: TcpsSdkTestTA_u.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -include sal_unsup.h -include stddef.h -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(APP_NAME) TcpsSdkTestTA_u.h TcpsSdkTestTA_u.c $(OBJECTS)
	@echo "Done."
