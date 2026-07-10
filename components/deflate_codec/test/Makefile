CC = gcc
CFLAGS = -Wall -Wextra -g -I../src
LDFLAGS = -lz

SRCS_DEFLATE = test_deflate_codec.c ../src/deflate_codec.c
TARGET_DEFLATE = test_deflate_codec

all: $(TARGET_DEFLATE)

$(TARGET_DEFLATE): $(SRCS_DEFLATE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET_DEFLATE)
	./$(TARGET_DEFLATE)

clean:
	rm -f $(TARGET_DEFLATE)

.PHONY: all run clean
