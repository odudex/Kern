CC = gcc
CFLAGS = -Wall -Wextra -g

ROOT = ../../../..
TARGET = test_bip_flow_register
TEST_INCS = -Istubs -I$(ROOT)/main -I$(ROOT)/main/core/test/stubs

all: $(TARGET)

$(TARGET): test_bip_flow_register.c ../bip_flow.h
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_register.c

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
