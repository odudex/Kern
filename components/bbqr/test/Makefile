CC = gcc
CFLAGS = -Wall -Wextra -g -I../src -I../../deflate_codec/src
LDFLAGS = -lz

SRCS_BBQR = test_bbqr.c ../src/base32.c ../../deflate_codec/src/deflate_codec.c ../src/bbqr.c
SRCS_BASE32 = test_base32.c ../src/base32.c
TARGET_BBQR = test_bbqr
TARGET_BASE32 = test_base32

all: $(TARGET_BBQR) $(TARGET_BASE32)

$(TARGET_BBQR): $(SRCS_BBQR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_BASE32): $(SRCS_BASE32)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET_BBQR) $(TARGET_BASE32)
	./$(TARGET_BASE32)
	./$(TARGET_BBQR)

run-bbqr: $(TARGET_BBQR)
	./$(TARGET_BBQR)

run-base32: $(TARGET_BASE32)
	./$(TARGET_BASE32)

clean:
	rm -f $(TARGET_BBQR) $(TARGET_BASE32)

.PHONY: all run run-bbqr run-base32 clean
