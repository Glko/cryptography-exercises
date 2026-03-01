# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -O2

# Automatically detect OpenSSL flags using pkg-config (fallback to manual flags)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Default target
all:
	@echo "Usage: make <target>"
	@echo "  make rsa_padding"
	@echo "  make df_params"
	@echo "  make all_targets   (builds both)"

all_targets: rsa_padding df_params

# Build rule for any .c file
%: %.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $< -o $@ $(OPENSSL_LIBS)

# Clean binaries
clean:
	rm -f rsa_padding df_params *.o *~

.PHONY: all all_targets clean
