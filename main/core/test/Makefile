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

WALLY_DEFS = -DBUILD_MINIMAL=1 -DBUILD_ELEMENTS=0 -DBUILD_STANDARD_SECP=1
WALLY_CFLAGS = $(WALLY_PRIV_INCS) $(WALLY_DEFS) \
	-Wno-nonnull-compare -Wno-unused-function -Wno-type-limits \
	-Wno-unterminated-string-initialization

# ESP-IDF stubs (esp_log.h etc.)
ESP_STUBS_INC = stubs

# Test includes: wally public headers + esp stubs + main source tree
TEST_INCS = -I$(WALLY_INC) -I$(ESP_STUBS_INC) -I$(ROOT)/main

# KEF pulls in crypto_utils/entropy_pool/deflate_codec, which need a handful of
# ESP-IDF headers.  Reuse the simulator's stub headers instead of a second copy;
# the implementations they declare live in stubs/esp_hw_stub.c.
SIM_STUBS_INC = $(ROOT)/simulator/platform/esp_idf_stubs/include
DEFLATE_DIR = $(ROOT)/components/deflate_codec/src
# Some distributions ship mbedTLS's pkcs5.h under mbedtls/private/; the shim in
# components/mbedtls_compat re-exports it, exactly as the simulator build does.
MBEDTLS_COMPAT_INC = $(shell test -e /usr/include/mbedtls/pkcs5.h || \
	echo -I$(ROOT)/components/mbedtls_compat)
# SIMULATOR routes PBKDF2 through mbedtls_pkcs5_pbkdf2_hmac_ext, since the host
# mbedTLS predates the PSA key-derivation API the firmware uses.
KEF_INCS = $(TEST_INCS) -I$(SIM_STUBS_INC) -I$(DEFLATE_DIR) \
	$(MBEDTLS_COMPAT_INC) -DSIMULATOR -include mbedtls_compat.h

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
DESCRIPTOR_CHECKSUM_SRC = ../descriptor_checksum.c ../descriptor_checksum.h
BIP32_PATH_SRC = ../bip32_path.c ../bip32_path.h
SCRIPT_TEMPLATE_SRC = ../script_templates.c ../script_templates.h
REGISTRY_STUB_SRC = stubs/registry_stub.c

SRCS_REG_PARSE = test_registry_parse.c
TARGET_REG_PARSE = test_registry_parse

PSBT_SRC = ../psbt.c ../psbt.h ../psbt_internal.h
SRCS_PSBT_CLASSIFY = test_psbt_classify.c
TARGET_PSBT_CLASSIFY = test_psbt_classify
PSBT_KEY_OBJ = test_psbt_key.o

SRCS_MS_POLICY = test_miniscript_policy.c
TARGET_MS_POLICY = test_miniscript_policy
MS_POLICY_SRC = ../miniscript_policy.c ../miniscript_policy.h

SRCS_BIP322 = test_bip322.c
TARGET_BIP322 = test_bip322
BIP322_SRC = ../bip322.c ../bip322.h

SRCS_ESTIMATED_ENTROPY = test_estimated_entropy.c
TARGET_ESTIMATED_ENTROPY = test_estimated_entropy
ESTIMATED_ENTROPY_SRC = ../../utils/estimated_entropy.c ../../utils/estimated_entropy.h
DICE_QUALITY_SRC = ../../utils/dice_quality.c ../../utils/dice_quality.h

SRCS_UTF8 = test_utf8.c
TARGET_UTF8 = test_utf8
UTF8_SRC = ../../utils/utf8.c ../../utils/utf8.h

SRCS_PIN_ATTEMPT = test_pin_attempt.c
TARGET_PIN_ATTEMPT = test_pin_attempt

SRCS_PSBT_PARSE = test_psbt_parse.c
TARGET_PSBT_PARSE = test_psbt_parse

SRCS_FW_UPDATE = test_fw_update.c
TARGET_FW_UPDATE = test_fw_update
FW_UPDATE_SRC = ../fw_update.c ../fw_update.h
FW_UPDATE_LIBS = -lmbedcrypto

SRCS_DESC_VALIDATOR = test_descriptor_validator.c
TARGET_DESC_VALIDATOR = test_descriptor_validator
DESC_VALIDATOR_SRC = ../descriptor_validator.c ../descriptor_validator.h \
	../wallet.c ../wallet.h ../miniscript_policy.c ../miniscript_policy.h

SRCS_STORAGE = test_storage.c
TARGET_STORAGE = test_storage
STORAGE_OBJ = test_storage_core.o
SD_CARD_INC = $(ROOT)/components/sd_card/include

SRCS_KEY = test_key.c
TARGET_KEY = test_key

SRCS_CRYPTO_UTILS = test_crypto_utils.c
TARGET_CRYPTO_UTILS = test_crypto_utils
CRYPTO_UTILS_SRC = ../crypto_utils.c ../crypto_utils.h ../entropy_pool.c \
	stubs/esp_hw_stub.c

SRCS_PBKDF2 = test_pbkdf2.c
TARGET_PBKDF2 = test_pbkdf2
PBKDF2_OBJ = test_pbkdf2_core.o

SRCS_KEF = test_kef.c
TARGET_KEF = test_kef
KEF_SRC = ../kef.c ../kef.h ../base43.c ../base43.h ../crypto_utils.c \
	../entropy_pool.c $(DEFLATE_DIR)/deflate_codec.c \
	stubs/esp_hw_stub.c
KEF_LIBS = -lmbedcrypto -lz

SS_SRC = ../ss_whitelist.c ../ss_whitelist.h $(SCRIPT_TEMPLATE_SRC)
KEY_SRC = ../key.c ../key.h $(BIP32_PATH_SRC) ../../utils/secure_mem.h
KEY_STUB_SRC = stubs/key_stub.c

all: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2)

$(LIBWALLY): $(WALLY_SRC) $(wildcard $(WALLY_DIR)/upstream/src/*.c)
	$(CC) $(CFLAGS) $(WALLY_CFLAGS) -c -o combined.o $<
	ar rcs $@ combined.o

$(TARGET_DERIV): $(SRCS_DERIV) $(BIP32_PATH_SRC)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_DERIV) ../bip32_path.c

$(TARGET_SS_PARSE): $(SRCS_SS_PARSE) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_PARSE) ../ss_whitelist.c ../script_templates.c $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_SS_WHITELISTED): $(SRCS_SS_WHITELISTED) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_WHITELISTED) ../ss_whitelist.c ../script_templates.c $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_SS_REGEN): $(SRCS_SS_REGEN) $(SS_SRC) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_SS_REGEN) ../key.c ../ss_whitelist.c ../bip32_path.c ../script_templates.c $(LIBWALLY)

$(TARGET_PSB): $(SRCS_PSB) $(SS_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PSB) ../ss_whitelist.c ../script_templates.c $(KEY_STUB_SRC) $(LIBWALLY)

$(TARGET_REG_MATCH): $(SRCS_REG_MATCH) $(REGISTRY_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_MATCH) ../registry.c ../bip32_path.c ../descriptor_checksum.c $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(TARGET_REG_PARSE): $(SRCS_REG_PARSE) $(REGISTRY_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_PARSE) ../registry.c ../bip32_path.c ../descriptor_checksum.c $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(PSBT_KEY_OBJ): $(KEY_SRC)
	$(CC) $(CFLAGS) $(TEST_INCS) -Dkey_get_fingerprint=key_get_fingerprint_raw -c -o $@ ../key.c

$(TARGET_PSBT_CLASSIFY): $(SRCS_PSBT_CLASSIFY) $(PSBT_SRC) $(SS_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(LIBWALLY) $(PSBT_KEY_OBJ)
	$(CC) $(CFLAGS) $(TEST_INCS) -DPSBT_TESTING -o $@ $(SRCS_PSBT_CLASSIFY) $(PSBT_KEY_OBJ) ../ss_whitelist.c ../registry.c ../psbt.c ../bip32_path.c ../script_templates.c ../descriptor_checksum.c $(LIBWALLY)

$(TARGET_PSBT_PARSE): $(SRCS_PSBT_PARSE) ../psbt_parse.c ../psbt.h $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PSBT_PARSE) ../psbt_parse.c $(LIBWALLY)

$(TARGET_MS_POLICY): $(SRCS_MS_POLICY) $(MS_POLICY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_MS_POLICY) ../miniscript_policy.c $(LIBWALLY)

$(TARGET_BIP322): $(SRCS_BIP322) $(BIP322_SRC) $(SCRIPT_TEMPLATE_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_BIP322) ../bip322.c ../script_templates.c $(LIBWALLY)

$(TARGET_ESTIMATED_ENTROPY): $(SRCS_ESTIMATED_ENTROPY) $(ESTIMATED_ENTROPY_SRC) $(DICE_QUALITY_SRC)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_ESTIMATED_ENTROPY) ../../utils/estimated_entropy.c ../../utils/dice_quality.c -lm

$(TARGET_UTF8): $(SRCS_UTF8) $(UTF8_SRC)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_UTF8) ../../utils/utf8.c

$(TARGET_PIN_ATTEMPT): $(SRCS_PIN_ATTEMPT) ../pin_attempt.h ../pin.h
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PIN_ATTEMPT)

$(TARGET_KEF): $(SRCS_KEF) $(KEF_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ $(SRCS_KEF) ../kef.c ../base43.c \
		../crypto_utils.c ../entropy_pool.c \
		$(DEFLATE_DIR)/deflate_codec.c \
		stubs/esp_hw_stub.c $(KEF_LIBS)

$(TARGET_FW_UPDATE): $(SRCS_FW_UPDATE) $(FW_UPDATE_SRC) $(wildcard stubs/*.h)
	$(CC) $(CFLAGS) $(TEST_INCS) -DCONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=1 \
		-o $@ $(SRCS_FW_UPDATE) ../fw_update.c $(FW_UPDATE_LIBS)

# The host compiler flags the %zu session-id suffix as truncatable; the
# firmware build carries -Wno-format for the same reason.
$(TARGET_DESC_VALIDATOR): $(SRCS_DESC_VALIDATOR) $(DESC_VALIDATOR_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(SS_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -Wno-format-truncation -o $@ $(SRCS_DESC_VALIDATOR) \
		../descriptor_validator.c ../wallet.c ../key.c ../registry.c \
		../descriptor_checksum.c ../bip32_path.c ../script_templates.c \
		../ss_whitelist.c ../miniscript_policy.c $(LIBWALLY)

# storage.c is built unchanged with its POSIX file calls redirected (see
# stubs/storage_host_hooks.h) so /spiffs and /sdcard resolve under a temp dir.
$(STORAGE_OBJ): ../storage.c ../storage.h stubs/storage_host_hooks.h
	$(CC) $(CFLAGS) $(KEF_INCS) -I$(SD_CARD_INC) -include stubs/storage_host_hooks.h \
		-c -o $@ ../storage.c

$(TARGET_STORAGE): $(SRCS_STORAGE) $(STORAGE_OBJ) $(KEF_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -I$(SD_CARD_INC) -o $@ $(SRCS_STORAGE) $(STORAGE_OBJ) \
		../kef.c ../base43.c ../crypto_utils.c ../entropy_pool.c \
		$(DEFLATE_DIR)/deflate_codec.c stubs/esp_hw_stub.c $(KEF_LIBS)

$(TARGET_KEY): $(SRCS_KEY) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_KEY) ../key.c ../bip32_path.c $(LIBWALLY)

$(TARGET_CRYPTO_UTILS): $(SRCS_CRYPTO_UTILS) $(CRYPTO_UTILS_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ $(SRCS_CRYPTO_UTILS) ../crypto_utils.c \
		../entropy_pool.c stubs/esp_hw_stub.c -lmbedcrypto

# pbkdf2.c is built unchanged with its PSA key-derivation calls routed to the
# test (see stubs/pbkdf2_host_hooks.h): the host mbedTLS has no PSA PBKDF2.
$(PBKDF2_OBJ): ../pbkdf2.c ../pbkdf2.h stubs/pbkdf2_host_hooks.h stubs/sha/sha_core.h stubs/hal/sha_types.h
	$(CC) $(CFLAGS) $(KEF_INCS) -include stubs/pbkdf2_host_hooks.h -c -o $@ ../pbkdf2.c

$(TARGET_PBKDF2): $(SRCS_PBKDF2) $(PBKDF2_OBJ) $(CRYPTO_UTILS_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ $(SRCS_PBKDF2) $(PBKDF2_OBJ) ../crypto_utils.c \
		../entropy_pool.c stubs/esp_hw_stub.c -lmbedcrypto

run: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2)
	./$(TARGET_DERIV)
	./$(TARGET_SS_PARSE)
	./$(TARGET_SS_WHITELISTED)
	./$(TARGET_SS_REGEN)
	./$(TARGET_PSB)
	./$(TARGET_REG_MATCH)
	./$(TARGET_REG_PARSE)
	./$(TARGET_PSBT_CLASSIFY)
	./$(TARGET_MS_POLICY)
	./$(TARGET_BIP322)
	./$(TARGET_ESTIMATED_ENTROPY)
	./$(TARGET_UTF8)
	./$(TARGET_PIN_ATTEMPT)
	./$(TARGET_KEF)
	./$(TARGET_PSBT_PARSE)
	./$(TARGET_FW_UPDATE)
	./$(TARGET_DESC_VALIDATOR)
	./$(TARGET_STORAGE)
	./$(TARGET_KEY)
	./$(TARGET_CRYPTO_UTILS)
	./$(TARGET_PBKDF2)

clean:
	rm -f $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2) $(LIBWALLY) combined.o $(PSBT_KEY_OBJ) $(STORAGE_OBJ) $(PBKDF2_OBJ)

.PHONY: all run clean
