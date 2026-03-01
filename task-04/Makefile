# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -O2

# Automatically detect OpenSSL flags using pkg-config
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

BIN = decrypt_aes_cbc_ssl
SRC = decrypt_aes_cbc_ssl.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $< -o $@ $(OPENSSL_LIBS)

clean:
	rm -f $(BIN) *.o *~

.PHONY: all clean
