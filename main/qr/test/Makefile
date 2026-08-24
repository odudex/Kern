CC ?= gcc
CFLAGS ?= -Wall -Wextra -g

REPO_ROOT := ../../..
INCLUDES := -I.. -I$(REPO_ROOT)/components/bbqr/src -I$(REPO_ROOT)/components/deflate_codec/src -I$(REPO_ROOT)/components/cUR/src

TARGETS := test_qr_parser

all: $(TARGETS)

test_qr_parser: test_qr_parser.c ../parser.c $(REPO_ROOT)/components/bbqr/src/bbqr.c $(REPO_ROOT)/components/bbqr/src/base32.c $(REPO_ROOT)/components/deflate_codec/src/deflate_codec.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lz -lm

run: all
	./test_qr_parser

clean:
	rm -f $(TARGETS)

.PHONY: all run clean
