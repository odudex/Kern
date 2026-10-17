CC ?= cc
CFLAGS = -Wall -Wextra -g

ROOT = ../../..
WALLY_DIR = $(ROOT)/components/libwally-core
WALLY_SRC = $(WALLY_DIR)/upstream/src/amalgamation/combined.c
WALLY_INC = $(WALLY_DIR)/upstream/include
WALLY_DEPS := $(WALLY_DIR)/config.h $(wildcard $(WALLY_INC)/*.h) \
	$(shell find $(WALLY_DIR)/upstream/src -name '*.[ch]' -o -name '*.inl' 2>/dev/null)

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

WALLY_DEFS = -DBUILD_MINIMAL=1 -DBUILD_STANDARD_SECP=1
WALLY_CFLAGS = $(WALLY_PRIV_INCS) $(WALLY_DEFS) \
	-Wno-nonnull-compare -Wno-unused-function -Wno-type-limits \
	-Wno-unterminated-string-initialization

# ESP-IDF stubs (esp_log.h etc.)
ESP_STUBS_INC = stubs

# Test includes: wally public headers + esp stubs + main source tree
TEST_INCS = -I$(ROOT)/components/bip138/include -I$(WALLY_INC) -I$(WALLY_DIR) -I$(ROOT)/components/secure_memory/include -I$(ESP_STUBS_INC) -I$(ROOT)/main

# KEF pulls in crypto_utils/entropy_pool/deflate_codec, which need a handful of
# ESP-IDF headers.  Reuse the simulator's stub headers instead of a second copy;
# the implementations they declare live in stubs/esp_hw_stub.c.
SIM_STUBS_INC = $(ROOT)/simulator/platform/esp_idf_stubs/include
DEFLATE_DIR = $(ROOT)/components/deflate_codec/src
# SIMULATOR routes PBKDF2 through mbedtls_pkcs5_pbkdf2_hmac_ext, since the host
# mbedTLS predates the PSA key-derivation API the firmware uses.
KEF_INCS = $(TEST_INCS) -I$(SIM_STUBS_INC) -I$(DEFLATE_DIR) \
	-DSIMULATOR -include mbedtls_compat.h
MBEDTLS_COMPAT_H = $(SIM_STUBS_INC)/mbedtls_compat.h

LIBWALLY = libwally.a

# Headers outside main/core that the tests compile, over-approximated: a full
# rebuild takes seconds.
COMMON_H = ../../utils/attributes.h $(shell find stubs $(SIM_STUBS_INC) -name '*.h') \
	$(DEFLATE_DIR)/deflate_codec.h $(SD_CARD_INC)/sd_card.h \
	$(wildcard $(BIP138_DIR)/include/*.h $(BIP138_DIR)/src/*.h)

# Each *_H is a header plus the main/core headers it includes.
SS_H = ../ss_whitelist.h ../bip32_path.h ../script_templates.h
REGISTRY_H = ../registry.h ../storage.h ../wallet.h $(SS_H)
PSBT_H = ../psbt.h $(REGISTRY_H)

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
REGISTRY_SRC = ../registry.c $(REGISTRY_H) ../descriptor_validator.h ../miniscript_policy.h \
	../bip138_backup.h ../bip138_keys.h ../descriptor_checksum.h ../key.h ../../utils/secure_mem.h
DESCRIPTOR_CHECKSUM_SRC = ../descriptor_checksum.c ../descriptor_checksum.h
BIP32_PATH_SRC = ../bip32_path.c $(SS_H)
SCRIPT_TEMPLATE_SRC = ../script_templates.c ../script_templates.h
REGISTRY_STUB_SRC = stubs/registry_stub.c
REGISTRY_PERSIST_STUB_SRC = stubs/registry_persist_stub.c
VALIDATOR_KEYED_STUB_SRC = stubs/validator_keyed_stub.c

SRCS_REG_PARSE = test_registry_parse.c
TARGET_REG_PARSE = test_registry_parse

PSBT_SRC = ../psbt.c ../psbt_internal.h ../key.h $(PSBT_H)
SRCS_PSBT_CLASSIFY = test_psbt_classify.c
TARGET_PSBT_CLASSIFY = test_psbt_classify
PSBT_KEY_OBJ = test_psbt_key.o

SRCS_MS_POLICY = test_miniscript_policy.c
TARGET_MS_POLICY = test_miniscript_policy
MS_POLICY_SRC = ../miniscript_policy.c ../miniscript_policy.h

SRCS_BIP322 = test_bip322.c
TARGET_BIP322 = test_bip322
BIP322_SRC = ../bip322.c ../bip322.h ../message_sign.c ../message_sign.h \
	../message_validation.h ../key.h ../../utils/secure_mem.h $(PSBT_H)

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
	../wallet.c ../wallet.h ../miniscript_policy.c ../miniscript_policy.h \
	../descriptor_checksum.h ../key.h ../psbt_internal.h $(PSBT_H)

SRCS_STORAGE = test_storage.c
TARGET_STORAGE = test_storage
STORAGE_OBJ = test_storage_core.o
SD_CARD_INC = $(ROOT)/components/sd_card/include

SRCS_KEY = test_key.c
TARGET_KEY = test_key

SRCS_CRYPTO_UTILS = test_crypto_utils.c
TARGET_CRYPTO_UTILS = test_crypto_utils
CRYPTO_UTILS_SRC = ../crypto_utils.c ../crypto_utils.h ../entropy_pool.c \
	../entropy_pool.h ../pbkdf2.h ../../utils/secure_mem.h stubs/esp_hw_stub.c \
	$(MBEDTLS_COMPAT_H)

SRCS_PBKDF2 = test_pbkdf2.c
TARGET_PBKDF2 = test_pbkdf2
PBKDF2_OBJ = test_pbkdf2_core.o

SRCS_KEF = test_kef.c
TARGET_KEF = test_kef
KEF_SRC = ../kef.c ../kef.h ../base43.c ../base43.h $(CRYPTO_UTILS_SRC) \
	$(DEFLATE_DIR)/deflate_codec.c
KEF_LIBS = -lmbedcrypto -lz

SS_SRC = ../ss_whitelist.c $(SS_H) ../key.h $(SCRIPT_TEMPLATE_SRC)
KEY_SRC = ../key.c ../key.h $(BIP32_PATH_SRC) ../../utils/secure_mem.h

BIP138_DIR = $(ROOT)/components/bip138
BIP138_SRCS = $(wildcard $(BIP138_DIR)/src/*.c)
BIP138_INCS = -I$(BIP138_DIR)/include -I$(BIP138_DIR)/test
SRCS_BIP138_KEYS = test_bip138_keys.c
TARGET_BIP138_KEYS = test_bip138_keys
SRCS_BIP138_BACKUP = test_bip138_backup.c
TARGET_BIP138_BACKUP = test_bip138_backup
KEY_STUB_SRC = stubs/key_stub.c

SRCS_ADDRESS_MATCH = test_address_match.c
TARGET_ADDRESS_MATCH = test_address_match
ADDRESS_MATCH_SRC = ../address_match.c ../address_match.h ../psbt_internal.h $(PSBT_H)

SRCS_MULTISIG_SETUP = test_multisig_setup.c
TARGET_MULTISIG_SETUP = test_multisig_setup
MULTISIG_SETUP_SRC = ../multisig_setup.c ../multisig_setup.h

all: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2) $(TARGET_BIP138_KEYS) $(TARGET_BIP138_BACKUP) $(TARGET_MULTISIG_SETUP) $(TARGET_ADDRESS_MATCH)

$(LIBWALLY): $(WALLY_SRC) $(WALLY_DEPS) $(WALLY_DIR)/kern_wally.c $(WALLY_DIR)/kern_wally.h $(ROOT)/components/secure_memory/secret_alloc.c $(ROOT)/components/secure_memory/include/secure_memory.h Makefile
	$(CC) $(CFLAGS) $(WALLY_CFLAGS) -c -o combined.o $<
	$(CC) $(CFLAGS) -I$(WALLY_INC) -I$(ROOT)/components/secure_memory/include -c -o kern_wally.o $(WALLY_DIR)/kern_wally.c
	$(CC) $(CFLAGS) -I$(ROOT)/components/secure_memory/include -c -o secret_alloc.o $(ROOT)/components/secure_memory/secret_alloc.c
	ar rcs $@ combined.o kern_wally.o secret_alloc.o

$(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2) $(TARGET_BIP138_KEYS) $(TARGET_BIP138_BACKUP) $(TARGET_MULTISIG_SETUP) $(TARGET_ADDRESS_MATCH) $(PSBT_KEY_OBJ) $(STORAGE_OBJ) $(PBKDF2_OBJ): $(COMMON_H)

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

$(TARGET_REG_MATCH): $(SRCS_REG_MATCH) $(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) $(BIP32_PATH_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_MATCH) ../registry.c $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) ../bip32_path.c ../descriptor_checksum.c $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(TARGET_REG_PARSE): $(SRCS_REG_PARSE) $(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) $(BIP32_PATH_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(REGISTRY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_REG_PARSE) ../registry.c $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) ../bip32_path.c ../descriptor_checksum.c $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(PSBT_KEY_OBJ): $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -Dkey_get_fingerprint=key_get_fingerprint_raw -c -o $@ ../key.c

$(TARGET_PSBT_CLASSIFY): $(SRCS_PSBT_CLASSIFY) ../settings.h $(PSBT_SRC) $(SS_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(LIBWALLY) $(PSBT_KEY_OBJ)
	$(CC) $(CFLAGS) $(TEST_INCS) -DPSBT_TESTING -o $@ $(SRCS_PSBT_CLASSIFY) $(PSBT_KEY_OBJ) ../ss_whitelist.c ../registry.c $(REGISTRY_PERSIST_STUB_SRC) $(VALIDATOR_KEYED_STUB_SRC) ../psbt.c ../bip32_path.c ../script_templates.c ../descriptor_checksum.c $(LIBWALLY)

$(TARGET_PSBT_PARSE): $(SRCS_PSBT_PARSE) ../psbt_parse.c $(PSBT_H) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_PSBT_PARSE) ../psbt_parse.c $(LIBWALLY)

$(TARGET_MS_POLICY): $(SRCS_MS_POLICY) $(MS_POLICY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_MS_POLICY) ../miniscript_policy.c $(LIBWALLY)

$(TARGET_BIP322): $(SRCS_BIP322) $(BIP322_SRC) $(SCRIPT_TEMPLATE_SRC) $(KEY_STUB_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_BIP322) ../bip322.c ../message_sign.c ../script_templates.c $(KEY_STUB_SRC) $(LIBWALLY)

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
$(TARGET_DESC_VALIDATOR): $(SRCS_DESC_VALIDATOR) $(DESC_VALIDATOR_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(REGISTRY_PERSIST_STUB_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(SS_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -Wno-format-truncation -o $@ $(SRCS_DESC_VALIDATOR) \
		../descriptor_validator.c ../wallet.c ../key.c ../registry.c $(REGISTRY_PERSIST_STUB_SRC) \
		../descriptor_checksum.c ../bip32_path.c ../script_templates.c \
		../ss_whitelist.c ../miniscript_policy.c $(LIBWALLY)

# storage.c is built unchanged with its POSIX file calls redirected (see
# stubs/storage_host_hooks.h) so /spiffs and /sdcard resolve under a temp dir.
$(STORAGE_OBJ): ../storage.c ../storage.h ../crypto_utils.h ../kef.h stubs/storage_host_hooks.h $(MBEDTLS_COMPAT_H)
	$(CC) $(CFLAGS) $(KEF_INCS) -I$(SD_CARD_INC) -include stubs/storage_host_hooks.h \
		-c -o $@ ../storage.c

$(TARGET_STORAGE): $(SRCS_STORAGE) $(STORAGE_OBJ) $(KEF_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -I$(SD_CARD_INC) -o $@ $(SRCS_STORAGE) $(STORAGE_OBJ) \
		../kef.c ../base43.c ../crypto_utils.c ../entropy_pool.c \
		$(DEFLATE_DIR)/deflate_codec.c stubs/esp_hw_stub.c $(KEF_LIBS)

$(TARGET_KEY): $(SRCS_KEY) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -pthread -Wl,--wrap=kern_secret_strdup -Wl,--wrap=kern_secret_alloc -Wl,--wrap=free -o $@ $(SRCS_KEY) ../key.c ../bip32_path.c $(LIBWALLY)

$(TARGET_CRYPTO_UTILS): $(SRCS_CRYPTO_UTILS) $(CRYPTO_UTILS_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ $(SRCS_CRYPTO_UTILS) ../crypto_utils.c \
		../entropy_pool.c stubs/esp_hw_stub.c -lmbedcrypto

# pbkdf2.c is built unchanged with its PSA key-derivation calls routed to the
# test (see stubs/pbkdf2_host_hooks.h): the host mbedTLS has no PSA PBKDF2.
$(PBKDF2_OBJ): ../pbkdf2.c ../pbkdf2.h ../crypto_utils.h ../../utils/secure_mem.h stubs/pbkdf2_host_hooks.h stubs/sha/sha_core.h stubs/hal/sha_types.h $(MBEDTLS_COMPAT_H)
	$(CC) $(CFLAGS) $(KEF_INCS) -include stubs/pbkdf2_host_hooks.h -c -o $@ ../pbkdf2.c

$(TARGET_PBKDF2): $(SRCS_PBKDF2) $(PBKDF2_OBJ) $(CRYPTO_UTILS_SRC)
	$(CC) $(CFLAGS) $(KEF_INCS) -o $@ $(SRCS_PBKDF2) $(PBKDF2_OBJ) ../crypto_utils.c \
		../entropy_pool.c stubs/esp_hw_stub.c -lmbedcrypto

$(TARGET_BIP138_KEYS): $(SRCS_BIP138_KEYS) ../bip138_keys.c ../bip138_keys.h ../bip32_path.h ../storage.h ../wallet.h $(REGISTRY_STUB_SRC) $(BIP138_DIR)/test/vectors.h $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) $(BIP138_INCS) -o $@ $(SRCS_BIP138_KEYS) ../bip138_keys.c $(REGISTRY_STUB_SRC) $(LIBWALLY)

$(TARGET_BIP138_BACKUP): $(SRCS_BIP138_BACKUP) ../bip138_backup.c ../bip138_backup.h ../bip138_keys.c ../bip138_keys.h ../bip138_crypto.c ../bip138_crypto.h $(CRYPTO_UTILS_SRC) $(KEY_SRC) $(REGISTRY_SRC) $(DESCRIPTOR_CHECKSUM_SRC) $(SS_SRC) $(DESC_VALIDATOR_SRC) $(BIP138_SRCS) $(LIBWALLY)
	$(CC) $(CFLAGS) $(KEF_INCS) $(BIP138_INCS) -Wno-format-truncation -o $@ $(SRCS_BIP138_BACKUP) \
		../bip138_backup.c ../bip138_keys.c ../bip138_crypto.c \
		../crypto_utils.c ../entropy_pool.c stubs/esp_hw_stub.c \
		../wallet.c ../key.c ../registry.c ../descriptor_validator.c ../descriptor_checksum.c ../bip32_path.c \
		../script_templates.c ../ss_whitelist.c ../miniscript_policy.c \
		$(BIP138_SRCS) $(LIBWALLY) $(KEF_LIBS)

$(TARGET_ADDRESS_MATCH): $(SRCS_ADDRESS_MATCH) $(ADDRESS_MATCH_SRC) $(SS_SRC) $(KEY_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -Wl,--wrap=wally_descriptor_to_script -o $@ $(SRCS_ADDRESS_MATCH) ../address_match.c ../ss_whitelist.c ../key.c ../bip32_path.c ../script_templates.c $(LIBWALLY)

$(TARGET_MULTISIG_SETUP): $(SRCS_MULTISIG_SETUP) $(MULTISIG_SETUP_SRC) $(LIBWALLY)
	$(CC) $(CFLAGS) $(TEST_INCS) -o $@ $(SRCS_MULTISIG_SETUP) ../multisig_setup.c $(LIBWALLY)

run: $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2) $(TARGET_BIP138_KEYS) $(TARGET_BIP138_BACKUP) $(TARGET_MULTISIG_SETUP) $(TARGET_ADDRESS_MATCH)
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
	./$(TARGET_BIP138_KEYS)
	./$(TARGET_BIP138_BACKUP)
	./$(TARGET_MULTISIG_SETUP)
	./$(TARGET_ADDRESS_MATCH)

clean:
	rm -f $(TARGET_DERIV) $(TARGET_SS_PARSE) $(TARGET_SS_WHITELISTED) $(TARGET_SS_REGEN) $(TARGET_PSB) $(TARGET_REG_MATCH) $(TARGET_REG_PARSE) $(TARGET_PSBT_CLASSIFY) $(TARGET_MS_POLICY) $(TARGET_BIP322) $(TARGET_ESTIMATED_ENTROPY) $(TARGET_UTF8) $(TARGET_PIN_ATTEMPT) $(TARGET_KEF) $(TARGET_PSBT_PARSE) $(TARGET_FW_UPDATE) $(TARGET_DESC_VALIDATOR) $(TARGET_STORAGE) $(TARGET_KEY) $(TARGET_CRYPTO_UTILS) $(TARGET_PBKDF2) $(TARGET_BIP138_KEYS) $(TARGET_BIP138_BACKUP) $(TARGET_MULTISIG_SETUP) $(TARGET_ADDRESS_MATCH) $(LIBWALLY) combined.o kern_wally.o secret_alloc.o $(PSBT_KEY_OBJ) $(STORAGE_OBJ) $(PBKDF2_OBJ)

.PHONY: all run clean
