# Compiler
CC = gcc

# Compiler flags
CFLAGS = -O0 -g -Wall -D_GNU_SOURCE

# Automatically detect OpenSSL flags using pkg-config
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lcrypto")

TARGET = openssl-pbkdf
SRC = openssl-pbkdf.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $< -o $@ $(OPENSSL_LIBS)

clean:
	rm -f $(TARGET) *.o *~ core

.PHONY: all clean
