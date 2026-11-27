CC = gcc
CFLAGS = -Wall -Wextra -g

ROOT = ../../../..
TARGET_REGISTER = test_bip_flow_register
TARGET_HEADER = test_bip_flow_header
TARGET_BIP388 = test_bip388
TARGET_LIANA = test_liana
BIP377_DIR = $(ROOT)/components/bip377
BIP377_SRCS = $(wildcard $(BIP377_DIR)/src/*.c)
TEST_INCS = -Istubs -I$(ROOT)/main -I$(ROOT)/main/core/test/stubs \
	-I$(BIP377_DIR)/include \
	-I$(ROOT)/components/libwally-core/upstream/include

all: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388) $(TARGET_LIANA)

$(TARGET_REGISTER): test_bip_flow_register.c ../bip_flow.h
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_register.c

$(TARGET_HEADER): test_bip_flow_header.c ../bip_flow.h $(BIP377_SRCS)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_header.c $(BIP377_SRCS)

$(TARGET_BIP388): test_bip388.c ../bip388.c ../bip388.h
	$(CC) $(CFLAGS) -o $@ test_bip388.c ../bip388.c

$(TARGET_LIANA): test_liana.c ../bip388.c ../bip388.h $(BIP377_SRCS)
	$(CC) $(CFLAGS) -I$(BIP377_DIR)/include -o $@ test_liana.c ../bip388.c $(BIP377_SRCS)

run: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388) $(TARGET_LIANA)
	./$(TARGET_REGISTER)
	./$(TARGET_HEADER)
	./$(TARGET_BIP388)
	./$(TARGET_LIANA)

clean:
	rm -f $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388) $(TARGET_LIANA)

.PHONY: all run clean
