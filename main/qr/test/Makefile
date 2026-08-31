CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -std=gnu11 -g
ROOT := ../../..
UR_DIR := $(ROOT)/components/cUR
UR_LIB := $(UR_DIR)/src/libur.a
INCLUDES := -I.. -I$(ROOT)/main -I$(ROOT)/components/bbqr/src \
	-I$(ROOT)/components/deflate_codec/src -I$(UR_DIR)/src
SOURCES := test_parser.c ../parser.c \
	$(ROOT)/components/bbqr/src/bbqr.c \
	$(ROOT)/components/bbqr/src/base32.c \
	$(ROOT)/components/deflate_codec/src/deflate_codec.c
TARGET := test_parser
# Wrapped so the tests can force an allocation failure on demand.
LDFLAGS := -Wl,--wrap=malloc

all: $(TARGET)

$(UR_LIB):
	$(MAKE) -C $(UR_DIR) all

$(TARGET): $(SOURCES) $(UR_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(UR_LIB) $(LDFLAGS) -lz -lm

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
