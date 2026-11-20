CC = gcc
CFLAGS = -Wall -Wextra -g

ROOT = ../../../..
TARGET_REGISTER = test_bip_flow_register
TARGET_HEADER = test_bip_flow_header
TARGET_BIP388 = test_bip388
TEST_INCS = -Istubs -I$(ROOT)/main -I$(ROOT)/main/core/test/stubs \
	-I$(ROOT)/components/bip377/upstream/bip377-ll/include \
	-I$(ROOT)/components/libwally-core/upstream/include
# kern-bip377 built for the host, shared with the core tests
KERN_BIP377_DIR = $(ROOT)/main/core/test/kern_bip377
KERN_BIP377 = $(KERN_BIP377_DIR)/release/libkern_bip377.a

all: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)

$(TARGET_REGISTER): test_bip_flow_register.c ../bip_flow.h
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_register.c

$(TARGET_HEADER): test_bip_flow_header.c ../bip_flow.h $(KERN_BIP377)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_header.c $(KERN_BIP377) -lpthread -ldl

$(TARGET_BIP388): test_bip388.c ../bip388.c ../bip388.h
	$(CC) $(CFLAGS) -o $@ test_bip388.c ../bip388.c

# Always runs: cargo tracks the crate sources and only relinks on a change
$(KERN_BIP377):
	CARGO_TARGET_DIR=$(KERN_BIP377_DIR) cargo build --release --manifest-path $(ROOT)/components/bip377/Cargo.toml

run: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)
	./$(TARGET_REGISTER)
	./$(TARGET_HEADER)
	./$(TARGET_BIP388)

clean:
	rm -f $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)

.PHONY: all run clean $(KERN_BIP377)
