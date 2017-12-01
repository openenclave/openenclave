CFLAGS += -pipe -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wno-unused-function -Wno-missing-braces -Wno-unused -Wno-overflow
CFLAGS += -Wno-unknown-pragmas -fno-builtin -frounding-math
CFLAGS += -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -Werror=pointer-arith
CFLAGS += -g
LDFLAGS += -g
LDLIBS += -lpthread -lm -lrt

# glibc specific settings
CFLAGS += -D_FILE_OFFSET_BITS=64
LDLIBS += -lcrypt -ldl -lresolv -lutil -lpthread

