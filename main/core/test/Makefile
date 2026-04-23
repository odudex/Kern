CC = gcc
CFLAGS = -Wall -Wextra -g

ROOT = ../../..
WALLY_DIR = $(ROOT)/components/libwally-core
WALLY_SRC = $(WALLY_DIR)/upstream/src/amalgamation/combined.c
WALLY_INC = $(WALLY_DIR)/upstream/include

WALLY_PRIV_INCS = \
	-I$(WALLY_DIR) \
	-I$(WALLY_DIR)/upstream \
	-I$(WALLY_DIR)/upstream/src \
	-I$(WALLY_DIR)/upstream/src/ccan \
	-I$(WALLY_DIR)/upstream/src/secp256k1 \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src \
	-I$(WALLY_DIR)/upstream/src/secp256k1/include \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/ecdh \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/ecdsa_adaptor \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/ecdsa_s2c \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/extrakeys \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/generator \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/musig \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/rangeproof \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/recovery \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/schnorrsig \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/surjection \
	-I$(WALLY_DIR)/upstream/src/secp256k1/src/modules/whitelist

WALLY_DEFS = -DBUILD_MINIMAL=1 -DBUILD_ELEMENTS=0
WALLY_CFLAGS = $(WALLY_PRIV_INCS) $(WALLY_DEFS) \
	-Wno-nonnull-compare -Wno-unused-function -Wno-type-limits \
	-Wno-unterminated-string-initialization

# ESP-IDF stubs (esp_log.h etc.)
ESP_STUBS_INC = stubs

# Test includes: wally public headers + esp stubs + main source tree
TEST_INCS = -I$(WALLY_INC) -I$(ESP_STUBS_INC) -I$(ROOT)/main

LIBWALLY = libwally.a

SRCS_DERIV = test_derivation_path.c
TARGET_DERIV = test_derivation_path

SRCS_SS_PARSE = test_ss_whitelist_parse.c
TARGET_SS_PARSE = test_ss_whitelist_parse

SRCS_SS_WHITELISTED = test_ss_whitelist_is_whitelisted.c
TARGET_SS_WHITELISTED = test_ss_whitelist_is_whitelisted

SRCS_SS_REGEN = test_ss_whitelist_regen.c
TARGET_SS_REGEN = test_ss_whitelist_regen

SRCS_PSB = test_purpose_binding.c
TARGET_PSB = test_purpose_binding

SRCS_REG_MATCH = test_registry_match.c
TARGET_REG_MATCH = test_registry_match
REGISTRY_SRC = ../registry.c ../registry.h
REGISTRY_STUB_SRC = stubs/registry_stub.c

SRCS_REG_PARSE = test_registry_parse.c
TARGET_REG_PARSE = test_registry_parse

PSBT_SRC = ../psbt.c ../psbt.h
SRCS_PSBT_CLASSIFY = test_psbt_classify.c
TARGET_PSBT_CLASSIFY = test_psbt_classify

SS_SRC = ../ss_whitelist.c ../ss_whitelist.h
KEY_SRC = ../key.c ../key.h ../../utils/secure_mem.h
KEY_STUB_SRC = stubs/key_stub.c

all: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY)

$(LIBWALLY): $(WALLY_SRC)
	$(CC) $(CFLAGS) $(WALLY_CFLAGS) -c -o combined.o $<
	ar rcs $@ combined.o

$(TARGET_DERIV): $(SRCS_DERIV) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_DERIV) $(LIBWALLY)

$(TARGET_SS_PARSE): $(SRCS_SS_PARSE) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_PARSE) $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_SS_WHITELISTED): $(SRCS_SS_WHITELISTED) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_WHITELISTED) $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_SS_REGEN): $(SRCS_SS_REGEN) $(SS_SRC) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_REGEN) $(LIBWALLY)

$(TARGET_PSB): $(SRCS_PSB) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PSB) $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_REG_MATCH): $(SRCS_REG_MATCH) $(REGISTRY_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_MATCH) $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(TARGET_REG_PARSE): $(SRCS_REG_PARSE) $(REGISTRY_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_PARSE) $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(TARGET_PSBT_CLASSIFY): $(SRCS_PSBT_CLASSIFY) $(PSBT_SRC) $(SS_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PSBT_CLASSIFY) $(LIBWALLY)

run: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY)
	./$(TARGET_DERIV)
	./$(TARGET_SS_PARSE)
	./$(TARGET_SS_WHITELISTED)
	./$(TARGET_SS_REGEN)
	./$(TARGET_PSB)
	./$(TARGET_REG_MATCH)
	./$(TARGET_REG_PARSE)
	./$(TARGET_PSBT_CLASSIFY)

clean:
	rm -f $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(LIBWALLY) combined.o

.PHONY: all run clean
