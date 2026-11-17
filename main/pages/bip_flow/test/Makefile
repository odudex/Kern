CC = gcc
CFLAGS = -Wall -Wextra -g

ROOT = ../../../..
TARGET_REGISTER = test_bip_flow_register
TARGET_HEADER = test_bip_flow_header
TARGET_BIP388 = test_bip388
TEST_INCS = -Istubs -I$(ROOT)/main -I$(ROOT)/main/core/test/stubs \
	-I$(ROOT)/components/bipqr/upstream/bipqr-ll/include \
	-I$(ROOT)/components/libwally-core/upstream/include
# kern-bipqr built for the host, shared with the core tests
KERN_BIPQR_DIR = $(ROOT)/main/core/test/kern_bipqr
KERN_BIPQR = $(KERN_BIPQR_DIR)/release/libkern_bipqr.a

all: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)

$(TARGET_REGISTER): test_bip_flow_register.c ../bip_flow.h
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_register.c

$(TARGET_HEADER): test_bip_flow_header.c ../bip_flow.h $(KERN_BIPQR)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ test_bip_flow_header.c $(KERN_BIPQR) -lpthread -ldl

$(TARGET_BIP388): test_bip388.c ../bip388.c ../bip388.h
	$(CC) $(CFLAGS) -o $@ test_bip388.c ../bip388.c

# Always runs: cargo tracks the crate sources and only relinks on a change
$(KERN_BIPQR):
	CARGO_TARGET_DIR=$(KERN_BIPQR_DIR) cargo build --release --manifest-path $(ROOT)/components/bipqr/Cargo.toml

run: $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)
	./$(TARGET_REGISTER)
	./$(TARGET_HEADER)
	./$(TARGET_BIP388)

clean:
	rm -f $(TARGET_REGISTER) $(TARGET_HEADER) $(TARGET_BIP388)

.PHONY: all run clean $(KERN_BIPQR)
