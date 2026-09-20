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
PROGRESS_TARGET := test_progress
YUV420_TARGET := test_yuv420
SIM_STUBS := $(ROOT)/simulator/platform/esp_idf_stubs
# Wrapped so the tests can force an allocation failure on demand.
LDFLAGS := -Wl,--wrap=malloc

all: $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET)

$(UR_LIB):
	$(MAKE) -C $(UR_DIR) all

$(TARGET): $(SOURCES) ../parser.h $(UR_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(UR_LIB) $(LDFLAGS) -lz -lm

$(PROGRESS_TARGET): test_progress.c ../progress.h ../parser.h $(SIM_STUBS)/freertos_sim.c
	$(CC) $(CFLAGS) -I$(SIM_STUBS)/include -o $@ test_progress.c $(SIM_STUBS)/freertos_sim.c -pthread

$(YUV420_TARGET): test_yuv420.c ../yuv420.h
	$(CC) $(CFLAGS) -o $@ test_yuv420.c

run: $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET)
	./$(TARGET)
	./$(PROGRESS_TARGET)
	./$(YUV420_TARGET)

clean:
	rm -f $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET)

.PHONY: all run clean
