CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -std=gnu11 -g
ROOT := ../../..
UR_DIR := $(ROOT)/components/cUR
UR_LIB := $(UR_DIR)/src/libur.a
INCLUDES := -I.. -I$(ROOT)/main -I$(ROOT)/components/bbqr/src \
	-I$(ROOT)/components/deflate_codec/src -I$(UR_DIR)/src
PARSER_SOURCES := ../parser.c \
	$(ROOT)/components/bbqr/src/bbqr.c \
	$(ROOT)/components/bbqr/src/base32.c \
	$(ROOT)/components/deflate_codec/src/deflate_codec.c
SOURCES := test_parser.c $(PARSER_SOURCES)
TARGET := test_parser
# Wrapped so the tests can force an allocation failure on demand.
LDFLAGS := -Wl,--wrap=malloc
# Carries its own UR decoder stubs, so it must not link libur.
QR_PARSER_SOURCES := test_qr_parser.c $(PARSER_SOURCES)
TARGET_QR_PARSER := test_qr_parser

all: $(TARGET) $(TARGET_QR_PARSER)

$(UR_LIB):
	$(MAKE) -C $(UR_DIR) all

$(TARGET): $(SOURCES) $(UR_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(UR_LIB) $(LDFLAGS) -lz -lm

$(TARGET_QR_PARSER): $(QR_PARSER_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(QR_PARSER_SOURCES) -lz -lm

run: $(TARGET) $(TARGET_QR_PARSER)
	./$(TARGET)
	./$(TARGET_QR_PARSER)

clean:
	rm -f $(TARGET) $(TARGET_QR_PARSER)
