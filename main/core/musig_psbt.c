#include "musig_psbt.h"

#include "bip32_path.h"
#include "descriptor_keys.h"
#include "key.h"
#include "nonce_cache.h"
#include "psbt_internal.h"
#include "registry.h"
#include "script_templates.h"
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_musig.h>
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>

/* BIP-371: libwally keeps it among the input's fields with no accessor */
#define PSBT_IN_TAP_MERKLE_ROOT 0x18
#define DERIVATION_PATH_FLAGS                                                  \
  (BIP32_FLAG_STR_WILDCARD | BIP32_FLAG_STR_BARE | BIP32_FLAG_STR_MULTIPATH)
#define BIP32_TWEAK_DATA_LEN (EC_PUBLIC_KEY_LEN + sizeof(uint32_t))
#define TAPSCRIPT_LEAF_VERSION 0xc0
#define COMPACT_SIZE_MAX_LEN 9
#define CONTROL_BLOCK_BASE_LEN (1 + EC_XONLY_PUBLIC_KEY_LEN)
#define CONTROL_BLOCK_MAX_DEPTH 128
/* BIP-342 sighash: the key version of BIP-342 public keys */
#define TAPSCRIPT_KEY_VERSION 0

/* True when a musig() key of `desc` has a participant of fingerprint `fp`. */
static bool descriptor_has_own_musig(const struct wally_descriptor *desc,
                                     const unsigned char *fp) {
  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK)
    return false;
  for (uint32_t i = 0; i < num_keys; i++) {
    if (descriptor_key_is_musig(desc, i) &&
        descriptor_key_holds_fingerprint(desc, i, fp))
      return true;
  }
  return false;
}

static bool entry_generates(const registry_entry_t *entry, uint32_t multi_index,
                            uint32_t child_num, const unsigned char *spk,
                            size_t spk_len) {
  /* Generation may use the buffer as workspace, as in claim_regenerate. */
  unsigned char script[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t written = 0;
  return wally_descriptor_to_script(entry->desc, 0, 0, 0, multi_index,
                                    child_num, 0, script, sizeof(script),
                                    &written) == WALLY_OK &&
         written == spk_len && memcmp(script, spk, spk_len) == 0;
}

/* The two unhardened steps an origin ends with: a child number, then the
 * child number of the wildcard. */
static bool origin_tail(const struct wally_map_item *item, uint32_t *tail) {
  uint32_t path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t path_len = 0;
  if (!bip32_path_from_keypath(item->value, item->value_len, path, &path_len,
                               MAX_KEYPATH_TOTAL_DEPTH) ||
      path_len < 2)
    return false;
  tail[0] = path[path_len - 2];
  tail[1] = path[path_len - 1];
  return !bip32_path_is_hardened(tail[0]) && !bip32_path_is_hardened(tail[1]);
}

/* True when the steps of `ref` at tuple position `multi_index` end with
 * `tail`. */
static bool key_steps_end_with(const struct wally_descriptor *desc,
                               descriptor_key_ref_t ref, uint32_t multi_index,
                               const uint32_t *tail) {
  uint32_t steps[MAX_KEYPATH_TOTAL_DEPTH];
  size_t n = 0;
  return descriptor_key_child_steps(desc, ref, multi_index, tail[1], steps,
                                    MAX_KEYPATH_TOTAL_DEPTH, &n) &&
         n >= 2 && steps[n - 2] == tail[0] && steps[n - 1] == tail[1];
}

/* True when a musig() key of ours ends with `tail` at tuple position
 * `multi_index`: on the musig()'s own path when it has one (aggregate then
 * derive), else on our participant's. The origin then names the position the
 * script is generated at, not just any position whose script matches. */
static bool own_musig_tail(const struct wally_descriptor *desc,
                           const unsigned char *our_fp, uint32_t multi_index,
                           const uint32_t *tail) {
  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK)
    return false;
  for (uint32_t i = 0; i < num_keys; i++) {
    if (!descriptor_key_is_musig(desc, i) ||
        !descriptor_key_holds_fingerprint(desc, i, our_fp))
      continue;
    descriptor_key_ref_t aggregate = {.index = i,
                                      .participant = DESCRIPTOR_KEY_NOT_MUSIG};
    if (key_steps_end_with(desc, aggregate, multi_index, tail))
      return true;
    size_t participants = descriptor_key_musig_participants(desc, i);
    for (size_t p = 0; p < participants; p++) {
      descriptor_key_ref_t ref = {.index = i, .participant = p};
      unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
      if (descriptor_key_origin_fingerprint(desc, ref, fp) &&
          memcmp(fp, our_fp, sizeof(fp)) == 0 &&
          key_steps_end_with(desc, ref, multi_index, tail))
        return true;
    }
  }
  return false;
}

static bool entry_claims(const registry_entry_t *entry,
                         const unsigned char *our_fp,
                         const struct wally_map *tap_paths,
                         const unsigned char *spk, size_t spk_len,
                         claim_t *claim_out) {
  for (size_t j = 0; j < tap_paths->num_items; j++) {
    uint32_t tail[2];
    if (!origin_tail(&tap_paths->items[j], tail))
      continue;
    for (uint32_t k = 0; k < entry->num_paths; k++) {
      if (!own_musig_tail(entry->desc, our_fp, k, tail) ||
          !entry_generates(entry, k, tail[1], spk, spk_len))
        continue;
      memset(claim_out, 0, sizeof(*claim_out));
      claim_out->kind = CLAIM_MUSIG;
      claim_out->registry.entry = entry;
      claim_out->registry.multi_index = k;
      claim_out->registry.child_num = tail[1];
      return true;
    }
  }
  return false;
}

bool musig_psbt_claim(const struct wally_map *tap_paths,
                      const unsigned char *spk, size_t spk_len,
                      claim_t *claim_out) {
  size_t spk_type = 0;
  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!tap_paths || !spk || !claim_out ||
      wally_scriptpubkey_get_type(spk, spk_len, &spk_type) != WALLY_OK ||
      spk_type != WALLY_SCRIPT_TYPE_P2TR || !key_get_fingerprint(our_fp))
    return false;

  for (size_t i = 0; i < registry_count(); i++) {
    const registry_entry_t *entry = registry_match_order_get(i);
    if (entry && entry->desc && descriptor_has_own_musig(entry->desc, our_fp) &&
        entry_claims(entry, our_fp, tap_paths, spk, spk_len, claim_out))
      return true;
  }
  return false;
}

/* A participant's compressed key at (multi_index, child_num), from its key
 * expression in the descriptor, and the derivation steps the expression adds
 * after the key. */
static bool participant_key(const struct wally_descriptor *desc,
                            descriptor_key_ref_t ref, uint32_t multi_index,
                            uint32_t child_num, unsigned char *pub_out,
                            uint32_t *steps, size_t *steps_len) {
  char *text = descriptor_key_string_alloc(desc, ref);
  if (!text)
    return false;
  const char *key = text;
  if (*key == '[') {
    const char *close = strchr(key, ']');
    key = close ? close + 1 : key + strlen(key);
  }
  const char *path = strchr(key, '/');
  size_t key_len = path ? (size_t)(path - key) : strlen(key);
  *steps_len = 0;

  bool ok;
  if (!path && key_len == 2 * EC_PUBLIC_KEY_LEN) {
    size_t written = 0;
    ok = wally_hex_n_to_bytes(key, key_len, pub_out, EC_PUBLIC_KEY_LEN,
                              &written) == WALLY_OK &&
         written == EC_PUBLIC_KEY_LEN;
  } else {
    struct ext_key xpub, child;
    ok = bip32_key_from_base58_n(key, key_len, &xpub) == WALLY_OK;
    /* past the '/': a bare path starts with a step */
    if (ok && path)
      ok = bip32_path_from_str_n(path + 1, strlen(path + 1), child_num,
                                 multi_index, DERIVATION_PATH_FLAGS, steps,
                                 MAX_KEYPATH_TOTAL_DEPTH,
                                 steps_len) == WALLY_OK &&
           *steps_len <= MAX_KEYPATH_TOTAL_DEPTH;
    if (ok && *steps_len)
      ok = bip32_key_from_parent_path(&xpub, steps, *steps_len,
                                      BIP32_FLAG_KEY_PUBLIC |
                                          BIP32_FLAG_SKIP_HASH,
                                      &child) == WALLY_OK;
    if (ok)
      memcpy(pub_out, *steps_len ? child.pub_key : xpub.pub_key,
             EC_PUBLIC_KEY_LEN);
    wally_bzero(&xpub, sizeof(xpub));
    wally_bzero(&child, sizeof(child));
  }
  wally_free_string(text);
  return ok;
}

static int compare_keys(const void *a, const void *b) {
  return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

/* The keys of every participant of the musig() at `key_index`, at
 * (multi_index, child_num), sorted as BIP-390 orders them for KeyAgg. The
 * caller frees them. */
static unsigned char *participant_keys_alloc(const registry_entry_t *entry,
                                             uint32_t key_index,
                                             uint32_t multi_index,
                                             uint32_t child_num,
                                             size_t *count_out) {
  size_t n = descriptor_key_musig_participants(entry->desc, key_index);
  unsigned char *keys = n ? malloc(n * EC_PUBLIC_KEY_LEN) : NULL;
  bool ok = keys != NULL;
  for (size_t p = 0; ok && p < n; p++) {
    descriptor_key_ref_t ref = {.index = key_index, .participant = p};
    uint32_t steps[MAX_KEYPATH_TOTAL_DEPTH];
    size_t steps_len = 0;
    ok = participant_key(entry->desc, ref, multi_index, child_num,
                         keys + p * EC_PUBLIC_KEY_LEN, steps, &steps_len);
  }
  if (!ok) {
    free(keys);
    return NULL;
  }
  qsort(keys, n, EC_PUBLIC_KEY_LEN, compare_keys);
  *count_out = n;
  return keys;
}

/* BIP-328: the plain tweaks of deriving the aggregate along the musig()
 * expression's own path, applied to the key aggregation. */
static bool apply_bip328_path(const registry_entry_t *entry, uint32_t key_index,
                              uint32_t multi_index, uint32_t child_num,
                              const unsigned char *aggregate,
                              struct wally_musig_keyagg_cache *cache) {
  char *path_str = NULL;
  if (wally_descriptor_get_key_child_path_str(entry->desc, key_index,
                                              &path_str) != WALLY_OK)
    return false;
  uint32_t steps[MAX_KEYPATH_TOTAL_DEPTH];
  size_t steps_len = 0;
  bool ok = true;
  if (path_str[0] != '\0')
    ok = bip32_path_from_str_n(path_str, strlen(path_str), child_num,
                               multi_index, DERIVATION_PATH_FLAGS, steps,
                               MAX_KEYPATH_TOTAL_DEPTH,
                               &steps_len) == WALLY_OK &&
         steps_len <= MAX_KEYPATH_TOTAL_DEPTH;
  wally_free_string(path_str);
  if (!ok || steps_len == 0)
    return ok;

  struct ext_key *synthetic = NULL;
  if (wally_musig_pubkey_to_xpub(aggregate, EC_PUBLIC_KEY_LEN,
                                 BIP32_VER_MAIN_PUBLIC, &synthetic) != WALLY_OK)
    return false;
  unsigned char data[BIP32_TWEAK_DATA_LEN];
  unsigned char hmac[HMAC_SHA512_LEN];
  unsigned char chain_code[WALLY_MUSIG2_CHAINCODE_LEN];
  memcpy(data, aggregate, EC_PUBLIC_KEY_LEN);
  memcpy(chain_code, synthetic->chain_code, sizeof(chain_code));
  bip32_key_free(synthetic);
  for (size_t i = 0; ok && i < steps_len; i++) {
    for (size_t b = 0; b < sizeof(uint32_t); b++)
      data[EC_PUBLIC_KEY_LEN + b] = (unsigned char)(steps[i] >> (24 - 8 * b));
    ok = !bip32_path_is_hardened(steps[i]) &&
         wally_hmac_sha512(chain_code, sizeof(chain_code), data, sizeof(data),
                           hmac, sizeof(hmac)) == WALLY_OK &&
         wally_musig_pubkey_ec_tweak_add(cache, hmac, EC_PRIVATE_KEY_LEN, data,
                                         EC_PUBLIC_KEY_LEN) == WALLY_OK;
    memcpy(chain_code, hmac + EC_PRIVATE_KEY_LEN, sizeof(chain_code));
  }
  return ok;
}

/* BIP-341: the taproot tweak of the internal key by the input's merkle root. */
static bool apply_taproot_tweak(const struct wally_psbt_input *input,
                                struct wally_musig_keyagg_cache *cache,
                                unsigned char *output_key) {
  unsigned char data[EC_XONLY_PUBLIC_KEY_LEN + SHA256_LEN];
  unsigned char internal[EC_PUBLIC_KEY_LEN];
  unsigned char tweak[SHA256_LEN];
  size_t data_len = EC_XONLY_PUBLIC_KEY_LEN;
  if (wally_musig_pubkey_get(cache, internal, sizeof(internal)) != WALLY_OK)
    return false;
  memcpy(data, internal + 1, EC_XONLY_PUBLIC_KEY_LEN);
  const struct wally_map_item *root =
      wally_map_get_integer(&input->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT);
  if (root) {
    if (root->value_len != SHA256_LEN)
      return false;
    memcpy(data + data_len, root->value, SHA256_LEN);
    data_len += SHA256_LEN;
  }
  return wally_bip340_tagged_hash(data, data_len, "TapTweak", tweak,
                                  sizeof(tweak)) == WALLY_OK &&
         wally_musig_pubkey_xonly_tweak_add(cache, tweak, sizeof(tweak),
                                            output_key,
                                            EC_PUBLIC_KEY_LEN) == WALLY_OK;
}

/* The key aggregation of the musig() at `key_index` for one input, with the
 * BIP-328 tweaks of a path after the musig(): the participants come from the
 * registered descriptor, sorted as BIP-390 orders them, never from the PSBT.
 * Writes the untweaked aggregate. */
static bool musig_key_agg(const registry_entry_t *entry, uint32_t key_index,
                          uint32_t multi_index, uint32_t child_num,
                          struct wally_musig_keyagg_cache **cache_out,
                          unsigned char *aggregate_out) {
  size_t n = 0;
  unsigned char *keys =
      participant_keys_alloc(entry, key_index, multi_index, child_num, &n);
  if (!keys)
    return false;

  unsigned char xonly[EC_XONLY_PUBLIC_KEY_LEN];
  struct wally_musig_keyagg_cache *cache = NULL;
  bool ok = wally_musig_pubkey_agg(keys, n * EC_PUBLIC_KEY_LEN, xonly,
                                   sizeof(xonly), &cache) == WALLY_OK &&
            wally_musig_pubkey_get(cache, aggregate_out, EC_PUBLIC_KEY_LEN) ==
                WALLY_OK &&
            apply_bip328_path(entry, key_index, multi_index, child_num,
                              aggregate_out, cache);
  free(keys);
  if (!ok) {
    wally_musig_keyagg_cache_free(cache);
    return false;
  }
  *cache_out = cache;
  return true;
}

/* The BIP-341 leaf hash of a tapscript. */
static bool tap_leaf_hash(uint8_t leaf_version, const unsigned char *script,
                          size_t script_len, unsigned char *hash_out) {
  size_t prefix_len = 0;
  unsigned char *data = malloc(1 + COMPACT_SIZE_MAX_LEN + script_len);
  if (!data)
    return false;
  data[0] = leaf_version;
  if (wally_varint_to_bytes(script_len, data + 1, COMPACT_SIZE_MAX_LEN,
                            &prefix_len) != WALLY_OK) {
    free(data);
    return false;
  }
  memcpy(data + 1 + prefix_len, script, script_len);
  bool ok =
      wally_bip340_tagged_hash(data, 1 + prefix_len + script_len, "TapLeaf",
                               hash_out, SHA256_LEN) == WALLY_OK;
  free(data);
  return ok;
}

/* BIP-341 script path verification: true when a TAP_LEAF_SCRIPT entry,
 * control block and tapscript, is a leaf of the tree the spent output key
 * commits to. Writes its leaf hash. */
static bool leaf_in_output(const struct wally_map_item *leaf,
                           const unsigned char *spk,
                           unsigned char *leaf_hash_out) {
  const unsigned char *control = leaf->key;
  size_t control_len = leaf->key_len;
  if (!control || control_len < CONTROL_BLOCK_BASE_LEN ||
      (control_len - CONTROL_BLOCK_BASE_LEN) % SHA256_LEN != 0 ||
      (control_len - CONTROL_BLOCK_BASE_LEN) / SHA256_LEN >
          CONTROL_BLOCK_MAX_DEPTH ||
      (control[0] & 0xfe) != TAPSCRIPT_LEAF_VERSION ||
      !tap_leaf_hash(TAPSCRIPT_LEAF_VERSION, leaf->value, leaf->value_len,
                     leaf_hash_out))
    return false;

  unsigned char node[SHA256_LEN], pair[2 * SHA256_LEN];
  memcpy(node, leaf_hash_out, SHA256_LEN);
  for (size_t off = CONTROL_BLOCK_BASE_LEN; off < control_len;
       off += SHA256_LEN) {
    bool node_first = memcmp(node, control + off, SHA256_LEN) < 0;
    memcpy(pair, node_first ? node : control + off, SHA256_LEN);
    memcpy(pair + SHA256_LEN, node_first ? control + off : node, SHA256_LEN);
    if (wally_bip340_tagged_hash(pair, sizeof(pair), "TapBranch", node,
                                 sizeof(node)) != WALLY_OK)
      return false;
  }
  unsigned char internal[EC_PUBLIC_KEY_LEN] = {0x02};
  unsigned char output[EC_PUBLIC_KEY_LEN];
  memcpy(internal + 1, control + 1, EC_XONLY_PUBLIC_KEY_LEN);
  return wally_ec_public_key_bip341_tweak(internal, sizeof(internal), node,
                                          sizeof(node), 0, output,
                                          sizeof(output)) == WALLY_OK &&
         memcmp(output + 1, spk + 2, EC_XONLY_PUBLIC_KEY_LEN) == 0 &&
         (output[0] == 0x03) == (control[0] & 1);
}

static const struct wally_map_item *slot_leaf(const struct wally_psbt *psbt,
                                              const musig_slot_t *slot) {
  const struct wally_map *leaves =
      &psbt->inputs[slot->input_index].taproot_leaf_scripts;
  return slot->has_leaf_hash && slot->leaf_item < leaves->num_items
             ? &leaves->items[slot->leaf_item]
             : NULL;
}

/* The key aggregation a slot signs with, checked against what it spends: for
 * the key path, with the taproot tweak, the spent output key; for a leaf, the
 * key its script pushes. */
static bool slot_key_agg(const struct wally_psbt *psbt,
                         const musig_slot_t *slot, const unsigned char *spk,
                         struct wally_musig_keyagg_cache **cache_out) {
  const struct wally_psbt_input *input = &psbt->inputs[slot->input_index];
  unsigned char aggregate[EC_PUBLIC_KEY_LEN], key[EC_PUBLIC_KEY_LEN];
  struct wally_musig_keyagg_cache *cache = NULL;
  if (!musig_key_agg(slot->entry, slot->key_index, slot->multi_index,
                     slot->child_num, &cache, aggregate))
    return false;
  const struct wally_map_item *leaf = slot_leaf(psbt, slot);
  bool ok =
      slot->has_leaf_hash
          ? leaf &&
                wally_musig_pubkey_get(cache, key, sizeof(key)) == WALLY_OK &&
                script_template_pushes_key(leaf->value, leaf->value_len,
                                           key + 1, EC_XONLY_PUBLIC_KEY_LEN)
          : apply_taproot_tweak(input, cache, key) &&
                memcmp(key + 1, spk + 2, EC_XONLY_PUBLIC_KEY_LEN) == 0;
  if (!ok) {
    wally_musig_keyagg_cache_free(cache);
    return false;
  }
  *cache_out = cache;
  return true;
}

/* The nonce cache key expression index of the key at `key_index`: the number
 * of key expressions before it holding a key of fingerprint `fp`, a musig()
 * counting once. libwally numbers keys in order of appearance, which is the
 * draft's order: the internal key, then the leaves left to right. */
static uint32_t key_expression_index(const struct wally_descriptor *desc,
                                     uint32_t key_index,
                                     const unsigned char *fp) {
  uint32_t index = 0;
  for (uint32_t i = 0; i < key_index; i++)
    index += descriptor_key_holds_fingerprint(desc, i, fp);
  return index;
}

/* Our participant `ref` of a musig(): its key at the slot's position, and the
 * path we derive its private key from, which must give that key. */
static bool own_participant(const registry_entry_t *entry,
                            descriptor_key_ref_t ref, musig_slot_t *slot) {
  uint32_t steps[MAX_KEYPATH_TOTAL_DEPTH];
  size_t steps_len = 0;
  if (!participant_key(entry->desc, ref, slot->multi_index, slot->child_num,
                       slot->participant, steps, &steps_len))
    return false;
  char *origin = descriptor_key_origin_path_alloc(entry->desc, ref);
  bool ok = origin && bip32_path_parse(origin, slot->path, &slot->path_len,
                                       MAX_KEYPATH_TOTAL_DEPTH);
  wally_free_string(origin);
  if (!ok || slot->path_len + steps_len > MAX_KEYPATH_TOTAL_DEPTH)
    return false;
  memcpy(slot->path + slot->path_len, steps, steps_len * sizeof(steps[0]));
  slot->path_len += steps_len;

  struct ext_key *derived = NULL;
  ok = key_get_signing_key(slot->path, slot->path_len, &derived) &&
       memcmp(derived->pub_key, slot->participant, EC_PUBLIC_KEY_LEN) == 0;
  bip32_key_free(derived);
  return ok;
}

static bool append_slot(musig_plan_t *plan, const musig_slot_t *slot) {
  musig_slot_t *slots =
      realloc(plan->slots, (plan->num_slots + 1) * sizeof(*slots));
  if (!slots)
    return false;
  plan->slots = slots;
  plan->slots[plan->num_slots++] = *slot;
  return true;
}

/* One slot per participant of ours of the slot's musig(). */
static musig_psbt_result_t add_own_participants(const musig_slot_t *slot,
                                                const unsigned char *our_fp,
                                                musig_plan_t *plan) {
  const struct wally_descriptor *desc = slot->entry->desc;
  size_t participants =
      descriptor_key_musig_participants(desc, slot->key_index);
  for (size_t p = 0; p < participants; p++) {
    descriptor_key_ref_t ref = {.index = slot->key_index, .participant = p};
    unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
    if (!descriptor_key_origin_fingerprint(desc, ref, fp) ||
        memcmp(fp, our_fp, sizeof(fp)) != 0)
      continue;
    musig_slot_t own = *slot;
    /* A fingerprint collision is not ours */
    if (own_participant(slot->entry, ref, &own) && !append_slot(plan, &own))
      return MUSIG_PSBT_ERR_INTERNAL;
  }
  return MUSIG_PSBT_OK;
}

/* The leaves of the input pushing the musig()'s key: every TAP_LEAF_SCRIPT is
 * proven against the spent output, so a leaf is the registered descriptor's. */
static musig_psbt_result_t
add_leaf_slots(const struct wally_psbt_input *input, musig_slot_t *slot,
               const struct wally_musig_keyagg_cache *cache,
               const unsigned char *spk, const unsigned char *our_fp,
               musig_plan_t *plan) {
  unsigned char key[EC_PUBLIC_KEY_LEN];
  if (wally_musig_pubkey_get(cache, key, sizeof(key)) != WALLY_OK)
    return MUSIG_PSBT_ERR_INTERNAL;
  memcpy(slot->aggregate, key, EC_PUBLIC_KEY_LEN);
  slot->has_leaf_hash = true;
  musig_psbt_result_t result = MUSIG_PSBT_OK;
  for (size_t j = 0;
       result == MUSIG_PSBT_OK && j < input->taproot_leaf_scripts.num_items;
       j++) {
    const struct wally_map_item *leaf = &input->taproot_leaf_scripts.items[j];
    if (!leaf_in_output(leaf, spk, slot->leaf_hash) ||
        !script_template_pushes_key(leaf->value, leaf->value_len, key + 1,
                                    EC_XONLY_PUBLIC_KEY_LEN))
      continue;
    slot->leaf_item = j;
    result = add_own_participants(slot, our_fp, plan);
  }
  return result;
}

/* The slots of one musig() key of a claimed input, when the input carries the
 * aggregate's PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, which is how a PSBT asks for
 * it: the key path for the tr() internal key (key index 0), every leaf pushing
 * its key otherwise. */
static musig_psbt_result_t
add_key_slots(const struct wally_psbt *psbt, size_t input_index,
              const claim_t *claim, uint32_t key_index,
              const unsigned char *spk, const unsigned char *our_fp,
              musig_plan_t *plan) {
  const registry_entry_t *entry = claim->registry.entry;
  const struct wally_psbt_input *input = &psbt->inputs[input_index];
  musig_slot_t slot = {
      .input_index = input_index,
      .entry = entry,
      .key_index = key_index,
      .multi_index = claim->registry.multi_index,
      .child_num = claim->registry.child_num,
      .key_expression_index =
          key_expression_index(entry->desc, key_index, our_fp),
  };
  unsigned char aggregate[EC_PUBLIC_KEY_LEN];
  struct wally_musig_keyagg_cache *cache = NULL;
  if (!musig_key_agg(entry, key_index, slot.multi_index, slot.child_num, &cache,
                     aggregate))
    return MUSIG_PSBT_ERR_INVALID;

  musig_psbt_result_t result = MUSIG_PSBT_OK;
  size_t asked = 0;
  if (key_index == 0) {
    struct wally_musig_keyagg_cache *tweaked = NULL;
    if (!slot_key_agg(psbt, &slot, spk, &tweaked) ||
        wally_musig_pubkey_get(tweaked, slot.aggregate, EC_PUBLIC_KEY_LEN) !=
            WALLY_OK)
      result = MUSIG_PSBT_ERR_INVALID;
    wally_musig_keyagg_cache_free(tweaked);
  }
  if (result == MUSIG_PSBT_OK &&
      wally_psbt_input_find_musig2_pubkey(input, aggregate, EC_PUBLIC_KEY_LEN,
                                          &asked) == WALLY_OK &&
      asked)
    result = key_index == 0
                 ? add_own_participants(&slot, our_fp, plan)
                 : add_leaf_slots(input, &slot, cache, spk, our_fp, plan);
  wally_musig_keyagg_cache_free(cache);
  return result;
}

static musig_psbt_result_t add_input_slots(const struct wally_psbt *psbt,
                                           size_t input_index,
                                           const unsigned char *our_fp,
                                           musig_plan_t *plan) {
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  size_t spk_len = 0;
  claim_t claim;
  if (!psbt_input_utxo_script(psbt, input_index, spk, sizeof(spk), &spk_len) ||
      !musig_psbt_claim(&psbt->inputs[input_index].taproot_leaf_paths, spk,
                        spk_len, &claim))
    return MUSIG_PSBT_OK;

  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(claim.registry.entry->desc, &num_keys) !=
      WALLY_OK)
    return MUSIG_PSBT_ERR_INTERNAL;
  for (uint32_t k = 0; k < num_keys; k++) {
    if (!descriptor_key_is_musig(claim.registry.entry->desc, k))
      continue;
    musig_psbt_result_t result =
        add_key_slots(psbt, input_index, &claim, k, spk, our_fp, plan);
    if (result != MUSIG_PSBT_OK)
      return result;
  }
  return MUSIG_PSBT_OK;
}

static const unsigned char *slot_leaf_hash(const musig_slot_t *slot) {
  return slot->has_leaf_hash ? slot->leaf_hash : NULL;
}

/* The PSBT_IN_MUSIG2_PUB_NONCE of `participant` for the slot's aggregate and
 * leaf, or NULL when the input has none of the right size. */
static const unsigned char *find_pubnonce(const struct wally_psbt_input *input,
                                          const unsigned char *participant,
                                          const musig_slot_t *slot) {
  size_t index = 0;
  if (wally_psbt_input_find_musig2_pubnonce(
          input, participant, EC_PUBLIC_KEY_LEN, slot->aggregate,
          EC_PUBLIC_KEY_LEN, slot_leaf_hash(slot),
          slot->has_leaf_hash ? SHA256_LEN : 0, &index) != WALLY_OK ||
      !index ||
      input->musig2_pubnonces.items[index - 1].value_len !=
          WALLY_MUSIG_PUBNONCE_LEN)
    return NULL;
  return input->musig2_pubnonces.items[index - 1].value;
}

/* The public nonces of every participant of the slot's musig(), in BIP-390
 * order, into `nonces`, sized for them. False when one is missing. */
static bool slot_pubnonces(const struct wally_psbt *psbt,
                           const musig_slot_t *slot, unsigned char *nonces,
                           size_t *count_out) {
  const struct wally_psbt_input *input = &psbt->inputs[slot->input_index];
  size_t n = 0;
  unsigned char *keys = participant_keys_alloc(
      slot->entry, slot->key_index, slot->multi_index, slot->child_num, &n);
  bool ok = keys != NULL;
  for (size_t p = 0; ok && p < n; p++) {
    const unsigned char *nonce =
        find_pubnonce(input, keys + p * EC_PUBLIC_KEY_LEN, slot);
    ok = nonce != NULL;
    if (ok && nonces)
      memcpy(nonces + p * WALLY_MUSIG_PUBNONCE_LEN, nonce,
             WALLY_MUSIG_PUBNONCE_LEN);
  }
  free(keys);
  if (ok)
    *count_out = n;
  return ok;
}

/* The step of one slot without a nonce cache session. */
static musig_step_t slot_step(const struct wally_psbt *psbt,
                              const musig_slot_t *slot) {
  size_t count = 0;
  if (!find_pubnonce(&psbt->inputs[slot->input_index], slot->participant, slot))
    return MUSIG_STEP_PUB_NONCES;
  return slot_pubnonces(psbt, slot, NULL, &count) ? MUSIG_STEP_PARTIAL_SIGS
                                                  : MUSIG_STEP_NOTHING;
}

/* The PSBT_GLOBAL_NONCE_CACHE_SESSION field, if the PSBT carries one. */
static musig_psbt_result_t session_field(const struct wally_psbt *psbt,
                                         musig_plan_t *plan, bool *found) {
  *found = false;
  for (size_t i = 0; i < psbt->unknowns.num_items; i++) {
    const struct wally_map_item *item = &psbt->unknowns.items[i];
    if (item->key_len == 0 ||
        item->key[0] != BNC_PSBT_GLOBAL_NONCE_CACHE_SESSION)
      continue;
    if (bnc_session_field_decode(item->key, item->key_len, item->value,
                                 item->value_len, plan->session_id,
                                 plan->session_ref) != BNC_OK)
      return MUSIG_PSBT_ERR_INVALID;
    *found = true;
  }
  return MUSIG_PSBT_OK;
}

/* The two-round session ID, from the canonical texts of the descriptors the
 * slots belong to. */
static musig_psbt_result_t two_round_session_id(bnc_signer *signer,
                                                musig_plan_t *plan) {
  char **texts = calloc(plan->num_slots, sizeof(*texts));
  if (!texts)
    return MUSIG_PSBT_ERR_INTERNAL;
  bool ok = true;
  for (size_t s = 0; ok && s < plan->num_slots; s++)
    ok = wally_descriptor_canonicalize(plan->slots[s].entry->desc,
                                       WALLY_MS_CANONICAL_NO_CHECKSUM,
                                       &texts[s]) == WALLY_OK;
  ok = ok &&
       bnc_two_round_session_id(signer, (const char *const *)texts,
                                plan->num_slots, plan->session_id) == BNC_OK;
  for (size_t s = 0; s < plan->num_slots; s++)
    wally_free_string(texts[s]);
  free(texts);
  return ok ? MUSIG_PSBT_OK : MUSIG_PSBT_ERR_INTERNAL;
}

static musig_psbt_result_t plan_step(const struct wally_psbt *psbt,
                                     musig_plan_t *plan) {
  if (plan->num_slots == 0)
    return MUSIG_PSBT_OK;
  bool cached = false;
  musig_psbt_result_t result = session_field(psbt, plan, &cached);
  if (result != MUSIG_PSBT_OK)
    return result;
  if (cached) {
    plan->step = MUSIG_STEP_CACHED;
    return MUSIG_PSBT_OK;
  }
  plan->step = MUSIG_STEP_NOTHING;
  for (size_t s = 0; s < plan->num_slots; s++) {
    musig_step_t step = slot_step(psbt, &plan->slots[s]);
    if (step > plan->step)
      plan->step = step;
  }
  bnc_signer *signer = nonce_cache_signer();
  if (!signer)
    return MUSIG_PSBT_ERR_INTERNAL;
  return two_round_session_id(signer, plan);
}

musig_psbt_result_t musig_psbt_plan(const struct wally_psbt *psbt,
                                    const bool *signable,
                                    musig_plan_t *plan_out) {
  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!psbt || !plan_out)
    return MUSIG_PSBT_ERR_INTERNAL;
  memset(plan_out, 0, sizeof(*plan_out));
  if (!key_get_fingerprint(our_fp))
    return MUSIG_PSBT_ERR_INTERNAL;

  musig_psbt_result_t result = MUSIG_PSBT_OK;
  for (size_t i = 0; result == MUSIG_PSBT_OK && i < psbt->num_inputs; i++) {
    if (!signable || signable[i])
      result = add_input_slots(psbt, i, our_fp, plan_out);
  }
  if (result == MUSIG_PSBT_OK)
    result = plan_step(psbt, plan_out);
  if (result != MUSIG_PSBT_OK)
    musig_plan_free(plan_out);
  return result;
}

void musig_plan_free(musig_plan_t *plan) {
  if (!plan)
    return;
  free(plan->slots);
  memset(plan, 0, sizeof(*plan));
}

/* Our participant's private key of the slot, wiped by bip32_key_free(). */
static bool slot_key(const musig_slot_t *slot, struct ext_key **key_out) {
  return key_get_signing_key(slot->path, slot->path_len, key_out);
}

static musig_psbt_result_t cached_nonce(bnc_signer *signer,
                                        const bnc_secret *secret,
                                        const musig_slot_t *slot,
                                        unsigned char *pubnonce_out) {
  struct ext_key *key = NULL;
  if (!slot_key(slot, &key))
    return MUSIG_PSBT_ERR_INTERNAL;
  int32_t status = bnc_cached_nonce(
      signer, secret, (uint32_t)slot->input_index, slot->key_expression_index,
      key->priv_key + 1, slot->participant, pubnonce_out);
  bip32_key_free(key);
  return status == BNC_OK ? MUSIG_PSBT_OK : MUSIG_PSBT_ERR_INTERNAL;
}

/* The slots a step signs: every one from a cached session, those with every
 * participant's public nonce in round 2. */
static bool step_signs_slot(const struct wally_psbt *psbt,
                            const musig_plan_t *plan,
                            const musig_slot_t *slot) {
  return plan->step == MUSIG_STEP_CACHED ||
         (plan->step == MUSIG_STEP_PARTIAL_SIGS &&
          slot_step(psbt, slot) == MUSIG_STEP_PARTIAL_SIGS);
}

static bool own_pubnonce(const struct wally_psbt *psbt,
                         const musig_slot_t *slot, unsigned char *pubnonce) {
  const unsigned char *nonce =
      find_pubnonce(&psbt->inputs[slot->input_index], slot->participant, slot);
  if (nonce)
    memcpy(pubnonce, nonce, WALLY_MUSIG_PUBNONCE_LEN);
  return nonce != NULL;
}

/* The secret the plan's step signs from: taken for signing, or only read. */
static musig_psbt_result_t plan_secret(bnc_signer *signer,
                                       const musig_plan_t *plan, bool take,
                                       bnc_secret **secret_out) {
  int32_t status;
  if (plan->step == MUSIG_STEP_CACHED)
    status = take ? bnc_begin_signing(signer, plan->session_id,
                                      plan->session_ref, secret_out)
                  : bnc_held_session(signer, plan->session_id,
                                     plan->session_ref, secret_out);
  else
    status = take
                 ? bnc_begin_round_two(signer, plan->session_id, secret_out)
                 : bnc_held_session(signer, plan->session_id, NULL, secret_out);
  switch (status) {
  case BNC_OK:
    return MUSIG_PSBT_OK;
  case BNC_ERR_UNKNOWN_SESSION:
  case BNC_ERR_SESSION_REF_MISMATCH:
    return MUSIG_PSBT_ERR_SESSION;
  default:
    return MUSIG_PSBT_ERR_INTERNAL;
  }
}

/* A slot the step signs needs our nonce to be the one the session gives, then
 * every participant's nonce. */
static musig_psbt_result_t check_slot_nonce(const struct wally_psbt *psbt,
                                            bnc_signer *signer,
                                            const bnc_secret *secret,
                                            const musig_slot_t *slot) {
  unsigned char expected[BNC_PUBNONCE_LEN], carried[BNC_PUBNONCE_LEN];
  size_t count = 0;
  musig_psbt_result_t result = cached_nonce(signer, secret, slot, expected);
  if (result != MUSIG_PSBT_OK)
    return result;
  if (!own_pubnonce(psbt, slot, carried) ||
      memcmp(expected, carried, sizeof(expected)) != 0)
    return MUSIG_PSBT_ERR_SESSION;
  if (!slot_pubnonces(psbt, slot, NULL, &count))
    return MUSIG_PSBT_ERR_INVALID;
  return MUSIG_PSBT_OK;
}

/* True when a slot of the plan is keyed by `item` of input `input_index`'s
 * PSBT_IN_MUSIG2_PUB_NONCE map: its participant, aggregate and leaf. */
static bool plan_keys_pubnonce(const musig_plan_t *plan, size_t input_index,
                               const struct wally_map_item *item) {
  for (size_t s = 0; s < plan->num_slots; s++) {
    const musig_slot_t *slot = &plan->slots[s];
    size_t key_len =
        2 * EC_PUBLIC_KEY_LEN + (slot->has_leaf_hash ? SHA256_LEN : 0);
    if (slot->input_index == input_index && item->key_len == key_len &&
        memcmp(item->key, slot->participant, EC_PUBLIC_KEY_LEN) == 0 &&
        memcmp(item->key + EC_PUBLIC_KEY_LEN, slot->aggregate,
               EC_PUBLIC_KEY_LEN) == 0 &&
        (!slot->has_leaf_hash || memcmp(item->key + 2 * EC_PUBLIC_KEY_LEN,
                                        slot->leaf_hash, SHA256_LEN) == 0))
      return true;
  }
  return false;
}

/* True when `participant` is the participant key of a slot of the plan. */
static bool plan_has_participant(const musig_plan_t *plan,
                                 const unsigned char *participant) {
  for (size_t s = 0; s < plan->num_slots; s++) {
    if (memcmp(plan->slots[s].participant, participant, EC_PUBLIC_KEY_LEN) == 0)
      return true;
  }
  return false;
}

/* A cached session prepared the nonces of the plan's slots only: a nonce of
 * one of our participant keys keyed by no slot is not one it gave. */
static musig_psbt_result_t check_unplanned_nonces(const struct wally_psbt *psbt,
                                                  const musig_plan_t *plan) {
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    const struct wally_map *nonces = &psbt->inputs[i].musig2_pubnonces;
    for (size_t j = 0; j < nonces->num_items; j++) {
      const struct wally_map_item *item = &nonces->items[j];
      if (item->key_len >= EC_PUBLIC_KEY_LEN &&
          plan_has_participant(plan, item->key) &&
          !plan_keys_pubnonce(plan, i, item))
        return MUSIG_PSBT_ERR_SESSION;
    }
  }
  return MUSIG_PSBT_OK;
}

musig_psbt_result_t musig_psbt_check_session(struct wally_psbt *psbt,
                                             const musig_plan_t *plan) {
  if (!psbt || !plan)
    return MUSIG_PSBT_ERR_INTERNAL;
  if (plan->step != MUSIG_STEP_CACHED && plan->step != MUSIG_STEP_PARTIAL_SIGS)
    return MUSIG_PSBT_OK;
  bnc_signer *signer = nonce_cache_signer();
  bnc_secret *secret = NULL;
  if (!signer)
    return MUSIG_PSBT_ERR_INTERNAL;
  musig_psbt_result_t result = plan_secret(signer, plan, false, &secret);
  if (result == MUSIG_PSBT_OK && plan->step == MUSIG_STEP_CACHED)
    result = check_unplanned_nonces(psbt, plan);
  for (size_t s = 0; result == MUSIG_PSBT_OK && s < plan->num_slots; s++) {
    if (step_signs_slot(psbt, plan, &plan->slots[s]))
      result = check_slot_nonce(psbt, signer, secret, &plan->slots[s]);
  }
  bnc_secret_free(secret);
  return result;
}

static musig_psbt_result_t round_one(struct wally_psbt *psbt,
                                     const musig_plan_t *plan,
                                     size_t *added_out) {
  bnc_signer *signer = nonce_cache_signer();
  uint8_t fresh[BNC_SECRET_LEN];
  bnc_secret *secret = NULL;
  if (!signer || !nonce_cache_fresh_secret(fresh))
    return MUSIG_PSBT_ERR_INTERNAL;
  int32_t status =
      bnc_begin_round_one(signer, plan->session_id, fresh, &secret);
  wally_bzero(fresh, sizeof(fresh));
  if (status != BNC_OK)
    return MUSIG_PSBT_ERR_INTERNAL;

  musig_psbt_result_t result = MUSIG_PSBT_OK;
  for (size_t s = 0; result == MUSIG_PSBT_OK && s < plan->num_slots; s++) {
    const musig_slot_t *slot = &plan->slots[s];
    unsigned char pubnonce[BNC_PUBNONCE_LEN];
    result = cached_nonce(signer, secret, slot, pubnonce);
    if (result == MUSIG_PSBT_OK &&
        wally_psbt_input_add_musig2_pubnonce(
            &psbt->inputs[slot->input_index], slot->participant,
            EC_PUBLIC_KEY_LEN, slot->aggregate, EC_PUBLIC_KEY_LEN,
            slot_leaf_hash(slot), slot->has_leaf_hash ? SHA256_LEN : 0,
            pubnonce, sizeof(pubnonce)) != WALLY_OK)
      result = MUSIG_PSBT_ERR_INTERNAL;
  }
  bnc_secret_free(secret);
  *added_out = result == MUSIG_PSBT_OK ? plan->num_slots : 0;
  return result;
}

/* BIP-342 sighash of a leaf: libwally's PSBT signature hash covers the key
 * path only. Every input's spent script and amount enter it. */
static musig_psbt_result_t leaf_sighash(const struct wally_psbt *psbt,
                                        const struct wally_tx *tx,
                                        const musig_slot_t *slot,
                                        uint32_t sighash_type,
                                        unsigned char *sighash) {
  const struct wally_map_item *leaf = slot_leaf(psbt, slot);
  uint64_t *values = calloc(psbt->num_inputs, sizeof(*values));
  struct wally_map scripts = {0};
  bool ok = leaf && values &&
            wally_map_init(psbt->num_inputs, NULL, &scripts) == WALLY_OK;
  for (size_t i = 0; ok && i < psbt->num_inputs; i++) {
    unsigned char spk[PSBT_MAX_INNER_SCRIPT_LEN];
    size_t spk_len = 0;
    ok = psbt_input_utxo_script(psbt, i, spk, sizeof(spk), &spk_len) &&
         wally_map_add_integer(&scripts, (uint32_t)i, spk, spk_len) == WALLY_OK;
    values[i] = psbt_get_input_value(psbt, i);
  }
  ok = ok && wally_tx_get_btc_taproot_signature_hash(
                 tx, slot->input_index, &scripts, values, psbt->num_inputs,
                 leaf->value, leaf->value_len, TAPSCRIPT_KEY_VERSION,
                 WALLY_NO_CODESEPARATOR, NULL, 0, sighash_type, 0, sighash,
                 SHA256_LEN) == WALLY_OK;
  wally_map_clear(&scripts);
  free(values);
  return ok ? MUSIG_PSBT_OK : MUSIG_PSBT_ERR_INVALID;
}

/* BIP-341 sighash the slot signs, of the input's PSBT_IN_SIGHASH_TYPE: BIP-327
 * signs any message and BIP-373 sets no rule, the aggregator appends the type
 * byte. Kern's review allows only ALL and DEFAULT, as for every signature. */
static musig_psbt_result_t slot_sighash(struct wally_psbt *psbt,
                                        const struct wally_tx *tx,
                                        const musig_slot_t *slot,
                                        unsigned char *sighash) {
  uint32_t sighash_type = psbt->inputs[slot->input_index].sighash;
  if (!psbt_sighash_is_supported(sighash_type))
    return MUSIG_PSBT_ERR_INVALID;
  if (slot->has_leaf_hash)
    return leaf_sighash(psbt, tx, slot,
                        sighash_type ? sighash_type : WALLY_SIGHASH_DEFAULT,
                        sighash);
  return wally_psbt_get_input_signature_hash(psbt, slot->input_index, tx, NULL,
                                             0, 0, sighash,
                                             SHA256_LEN) == WALLY_OK
             ? MUSIG_PSBT_OK
             : MUSIG_PSBT_ERR_INVALID;
}

/* The BIP-327 session context of a slot: its tweaked key aggregation, and
 * the session of every participant's nonce and the sighash. */
static musig_psbt_result_t slot_context(struct wally_psbt *psbt,
                                        const struct wally_tx *tx,
                                        const musig_slot_t *slot,
                                        struct wally_musig_keyagg_cache **cache,
                                        struct wally_musig_session **session) {
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  unsigned char sighash[SHA256_LEN];
  size_t spk_len = 0, count = 0;
  size_t n =
      descriptor_key_musig_participants(slot->entry->desc, slot->key_index);
  unsigned char *nonces = malloc(n * WALLY_MUSIG_PUBNONCE_LEN);
  struct wally_musig_aggnonce *aggnonce = NULL;
  musig_psbt_result_t result = slot_sighash(psbt, tx, slot, sighash);
  if (!nonces)
    result = MUSIG_PSBT_ERR_INTERNAL;
  if (result == MUSIG_PSBT_OK &&
      (!psbt_input_utxo_script(psbt, slot->input_index, spk, sizeof(spk),
                               &spk_len) ||
       !slot_key_agg(psbt, slot, spk, cache) ||
       !slot_pubnonces(psbt, slot, nonces, &count)))
    result = MUSIG_PSBT_ERR_INVALID;
  if (result == MUSIG_PSBT_OK &&
      (wally_musig_nonce_agg(nonces, count * WALLY_MUSIG_PUBNONCE_LEN, count,
                             &aggnonce) != WALLY_OK ||
       wally_musig_nonce_process(aggnonce, sighash, sizeof(sighash), *cache,
                                 NULL, 0, session) != WALLY_OK))
    result = MUSIG_PSBT_ERR_INVALID;
  wally_musig_aggnonce_free(aggnonce);
  free(nonces);
  return result;
}

static musig_psbt_result_t
sign_slot(struct wally_psbt *psbt, const struct wally_tx *tx,
          bnc_signer *signer, const bnc_secret *secret,
          const musig_slot_t *slot, unsigned char *partial_sig) {
  struct wally_musig_keyagg_cache *cache = NULL;
  struct wally_musig_session *session = NULL;
  struct ext_key *key = NULL;
  bnc_musig_slot bnc_slot = {
      .input_index = (uint32_t)slot->input_index,
      .key_expression_index = slot->key_expression_index,
  };
  memcpy(bnc_slot.participant, slot->participant, BNC_PUBLIC_KEY_LEN);
  musig_psbt_result_t result =
      own_pubnonce(psbt, slot, bnc_slot.pubnonce)
          ? slot_context(psbt, tx, slot, &cache, &session)
          : MUSIG_PSBT_ERR_SESSION;
  if (result == MUSIG_PSBT_OK && !slot_key(slot, &key))
    result = MUSIG_PSBT_ERR_INTERNAL;
  if (result == MUSIG_PSBT_OK) {
    nonce_cache_sign_context_t context = {.keyagg_cache = cache,
                                          .session = session};
    int32_t status = bnc_sign_musig(signer, secret, &bnc_slot,
                                    key->priv_key + 1, &context, partial_sig);
    if (status == BNC_ERR_PUBNONCE_MISMATCH)
      result = MUSIG_PSBT_ERR_SESSION;
    else if (status != BNC_OK)
      result = MUSIG_PSBT_ERR_INTERNAL;
  }
  bip32_key_free(key);
  wally_musig_session_free(session);
  wally_musig_keyagg_cache_free(cache);
  return result;
}

/* Signs every slot the step asks with the session taken, deleted durably
 * before this returns, and writes the partial signatures once all are made. */
static musig_psbt_result_t sign_slots(struct wally_psbt *psbt,
                                      const musig_plan_t *plan,
                                      size_t *added_out) {
  bnc_signer *signer = nonce_cache_signer();
  if (!signer)
    return MUSIG_PSBT_ERR_INTERNAL;
  bool *signs = calloc(plan->num_slots, sizeof(*signs));
  unsigned char *partial_sigs =
      calloc(plan->num_slots, WALLY_MUSIG_PARTIAL_SIG_LEN);
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  bnc_secret *secret = NULL;
  musig_psbt_result_t result =
      signs && partial_sigs && tx ? MUSIG_PSBT_OK : MUSIG_PSBT_ERR_INTERNAL;
  for (size_t s = 0; result == MUSIG_PSBT_OK && s < plan->num_slots; s++)
    signs[s] = step_signs_slot(psbt, plan, &plan->slots[s]);
  if (result == MUSIG_PSBT_OK)
    result = plan_secret(signer, plan, true, &secret);
  for (size_t s = 0; result == MUSIG_PSBT_OK && s < plan->num_slots; s++) {
    if (signs[s])
      result = sign_slot(psbt, tx, signer, secret, &plan->slots[s],
                         partial_sigs + s * WALLY_MUSIG_PARTIAL_SIG_LEN);
  }
  bnc_secret_free(secret);

  size_t added = 0;
  for (size_t s = 0; result == MUSIG_PSBT_OK && s < plan->num_slots; s++) {
    const musig_slot_t *slot = &plan->slots[s];
    if (!signs[s])
      continue;
    if (wally_psbt_input_add_musig2_partial_sig(
            &psbt->inputs[slot->input_index], slot->participant,
            EC_PUBLIC_KEY_LEN, slot->aggregate, EC_PUBLIC_KEY_LEN,
            slot_leaf_hash(slot), slot->has_leaf_hash ? SHA256_LEN : 0,
            partial_sigs + s * WALLY_MUSIG_PARTIAL_SIG_LEN,
            WALLY_MUSIG_PARTIAL_SIG_LEN) != WALLY_OK)
      result = MUSIG_PSBT_ERR_INTERNAL;
    added++;
  }
  wally_tx_free(tx);
  free(partial_sigs);
  free(signs);
  *added_out = result == MUSIG_PSBT_OK ? added : 0;
  return result;
}

musig_psbt_result_t musig_psbt_sign(struct wally_psbt *psbt,
                                    const musig_plan_t *plan,
                                    size_t *added_out) {
  if (!psbt || !plan || !added_out)
    return MUSIG_PSBT_ERR_INTERNAL;
  *added_out = 0;
  switch (plan->step) {
  case MUSIG_STEP_NONE:
  case MUSIG_STEP_NOTHING:
    return MUSIG_PSBT_OK;
  case MUSIG_STEP_PUB_NONCES:
    return round_one(psbt, plan, added_out);
  case MUSIG_STEP_PARTIAL_SIGS:
  case MUSIG_STEP_CACHED:
    return sign_slots(psbt, plan, added_out);
  }
  return MUSIG_PSBT_ERR_INTERNAL;
}

/* True when an input of ours is to sign outside MuSig2. */
static bool signs_other_inputs(const struct wally_psbt *psbt, bool is_testnet) {
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    input_ownership_t owner = psbt_classify_input(psbt, i, is_testnet);
    if (owner.ownership != PSBT_OWNERSHIP_EXTERNAL &&
        owner.claim.kind != CLAIM_MUSIG)
      return true;
  }
  return false;
}

musig_psbt_result_t musig_psbt_check_request(const uint8_t *psbt_bytes,
                                             size_t psbt_len, bool is_testnet) {
  struct wally_psbt *psbt = NULL;
  if (!psbt_parse_payload(psbt_bytes, psbt_len, &psbt))
    return MUSIG_PSBT_OK;
  musig_plan_t plan;
  musig_psbt_result_t result = musig_psbt_plan(psbt, NULL, &plan);
  if (result == MUSIG_PSBT_OK)
    result = musig_psbt_check_session(psbt, &plan);
  if (result == MUSIG_PSBT_OK && plan.step == MUSIG_STEP_NOTHING &&
      !signs_other_inputs(psbt, is_testnet))
    result = MUSIG_PSBT_ERR_NOTHING;
  musig_plan_free(&plan);
  wally_psbt_free(psbt);
  return result;
}

/* True when our participant `ref` is the key at `path`. */
static bool participant_at_path(const struct wally_descriptor *desc,
                                descriptor_key_ref_t ref, const uint32_t *path,
                                size_t path_len) {
  uint32_t origin[MAX_KEYPATH_TOTAL_DEPTH];
  size_t origin_len = 0;
  char *origin_str = descriptor_key_origin_path_alloc(desc, ref);
  bool ok = origin_str && bip32_path_parse(origin_str, origin, &origin_len,
                                           MAX_KEYPATH_TOTAL_DEPTH);
  wally_free_string(origin_str);
  if (!ok || path_len < origin_len ||
      memcmp(path, origin, origin_len * sizeof(origin[0])) != 0)
    return false;

  uint32_t num_paths = 0;
  if (wally_descriptor_get_num_paths(desc, &num_paths) != WALLY_OK)
    return false;
  /* The step before the child number is a child number too: the position in
   * the <a;b> tuple is the one whose steps `path` ends with. */
  uint32_t child_num = path_len >= origin_len + 2 ? path[path_len - 1] : 0;
  for (uint32_t k = 0; k < num_paths; k++) {
    unsigned char key[EC_PUBLIC_KEY_LEN];
    uint32_t steps[MAX_KEYPATH_TOTAL_DEPTH];
    size_t steps_len = 0;
    if (participant_key(desc, ref, k, child_num, key, steps, &steps_len) &&
        origin_len + steps_len == path_len &&
        memcmp(path + origin_len, steps, steps_len * sizeof(steps[0])) == 0)
      return true;
  }
  return false;
}

bool musig_psbt_is_participant_path(const struct wally_descriptor *desc,
                                    const uint32_t *path, size_t path_len) {
  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  uint32_t num_keys = 0;
  if (!desc || !path || !key_get_fingerprint(our_fp) ||
      wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK)
    return false;
  for (uint32_t k = 0; k < num_keys; k++) {
    size_t participants = descriptor_key_musig_participants(desc, k);
    for (size_t p = 0; p < participants; p++) {
      descriptor_key_ref_t ref = {.index = k, .participant = p};
      unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
      if (descriptor_key_origin_fingerprint(desc, ref, fp) &&
          memcmp(fp, our_fp, sizeof(fp)) == 0 &&
          participant_at_path(desc, ref, path, path_len))
        return true;
    }
  }
  return false;
}

bool musig_psbt_is_own_participant(const struct wally_psbt *psbt,
                                   size_t input_index,
                                   const unsigned char *participant) {
  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  musig_plan_t plan = {0};
  if (!psbt || !participant || input_index >= psbt->num_inputs ||
      !key_get_fingerprint(our_fp) ||
      add_input_slots(psbt, input_index, our_fp, &plan) != MUSIG_PSBT_OK) {
    musig_plan_free(&plan);
    return false;
  }
  bool own = false;
  for (size_t s = 0; !own && s < plan.num_slots; s++)
    own =
        memcmp(plan.slots[s].participant, participant, EC_PUBLIC_KEY_LEN) == 0;
  musig_plan_free(&plan);
  return own;
}
