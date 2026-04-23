#ifndef SS_WHITELIST_H
#define SS_WHITELIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  SS_SCRIPT_P2PKH = 0,   // BIP44, purpose 44
  SS_SCRIPT_P2SH_P2WPKH, // BIP49, purpose 49
  SS_SCRIPT_P2WPKH,      // BIP84, purpose 84
  SS_SCRIPT_P2TR,        // BIP86, purpose 86 (single-key)
} ss_script_type_t;

typedef enum {
  PSB_OK,   /* purpose matches the conventional outer script */
  PSB_WARN, /* purpose ∈ {44,48,49,84,86} but outer script does not match */
  PSB_NA,   /* purpose not in {44,48,49,84,86} — no convention to check */
} psb_result_t;

struct wally_descriptor; /* opaque; defined in wally_descriptor.h */

typedef struct {
  ss_script_type_t script;
  uint32_t purpose; // 44/49/84/86 (unhardened)
  uint32_t coin;    // 0 or 1 (unhardened)
  uint32_t account; // 0..SS_MAX_ACCOUNT (unhardened)
  uint32_t chain;   // 0 or 1 (unhardened)
  uint32_t index;   // < SS_MAX_ADDR_INDEX (unhardened)
} ss_keypath_t;

#define SS_MAX_ACCOUNT 100
#define SS_MAX_ADDR_INDEX 100

#define MAX_KEYPATH_ORIGIN_DEPTH 6
#define MAX_KEYPATH_TAIL_DEPTH 2
#define MAX_KEYPATH_TOTAL_DEPTH                                                \
  (MAX_KEYPATH_ORIGIN_DEPTH + MAX_KEYPATH_TAIL_DEPTH)

static inline bool ss_is_hardened(uint32_t component) {
  return (component & 0x80000000u) != 0;
}

static inline uint32_t ss_unharden(uint32_t component) {
  return component & 0x7fffffffu;
}

static inline uint32_t ss_u32_le(const unsigned char *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

bool ss_keypath_parse(const unsigned char *keypath_after_fp,
                      size_t keypath_len_after_fp, ss_keypath_t *out);

/* Maximum buffer size for ss_keypath_format output ("m/86'/1'/100'/1/99\0" = 19
 * bytes). */
#define SS_KEYPATH_FMT_MAX 32

#define SS_P2SH_P2WPKH_REDEEM_LEN 22 /* OP_0 <20-byte pkh> */
#define SS_P2SH_P2WPKH_SPK_LEN 23    /* OP_HASH160 <20-byte hash> OP_EQUAL */

bool ss_keypath_format(const ss_keypath_t *kp, char *buf, size_t buf_size);

bool ss_keypath_is_whitelisted(const ss_keypath_t *kp, bool is_testnet);

bool ss_scriptpubkey(ss_script_type_t script, uint32_t account, uint32_t chain,
                     uint32_t index, bool is_testnet, uint8_t *out,
                     size_t *out_len);

/*
 * Like ss_scriptpubkey but also writes the redeem script into
 * redeem_out/redeem_len for SS_SCRIPT_P2SH_P2WPKH inputs. For all other script
 * types, *redeem_len is set to 0 and behaviour matches ss_scriptpubkey.
 * redeem_out must have room for SS_P2SH_P2WPKH_REDEEM_LEN bytes.
 */
bool ss_scriptpubkey_with_redeem(ss_script_type_t script, uint32_t account,
                                 uint32_t chain, uint32_t index,
                                 bool is_testnet, uint8_t *spk_out,
                                 size_t *spk_len, uint8_t *redeem_out,
                                 size_t *redeem_len);

/* Maximum buffer size for ss_address output (covers all script types + null).
 */
#define SS_ADDRESS_MAX_LEN 75

bool ss_address(ss_script_type_t script, uint32_t account, uint32_t chain,
                uint32_t index, bool is_testnet, char *address_out,
                size_t address_out_len);

/*
 * Returns true iff (purpose, outer_script) matches the fixed BIP convention:
 *   44 ↔ SS_SCRIPT_P2PKH
 *   49 ↔ SS_SCRIPT_P2SH_P2WPKH
 *   84 ↔ SS_SCRIPT_P2WPKH
 *   86 ↔ SS_SCRIPT_P2TR
 * Any other combination returns false.
 * Used by try_match_whitelist (hard enforcement — mismatch means no claim).
 */
bool purpose_script_binding_check_strict(uint32_t purpose,
                                         ss_script_type_t outer_script);

/*
 * Inspects a parsed descriptor's outer script type (via canonicalisation)
 * and the origin purpose of key[0]. Returns:
 *   PSB_OK   — purpose matches outer script convention
 *   PSB_WARN — purpose in {44,48,49,84,86} but outer script differs (show
 * warning dialog) PSB_NA   — purpose not in {44,48,49,84,86} (no convention
 * applies) Used by the descriptor registration UI.
 */
psb_result_t
purpose_script_binding_check_soft(const struct wally_descriptor *desc);

#endif // SS_WHITELIST_H
