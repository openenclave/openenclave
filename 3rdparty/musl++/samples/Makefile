CC=/opt/musl++/bin/musl-gcc
CXX=/opt/musl++/bin/musl-g++

all: hello goodbye

hello: hello.cpp
	$(CXX) -o hello hello.cpp

goodbye: goodbye.c
	$(CC) -o goodbye goodbye.c

clean:
	rm -rf hello goodbye
