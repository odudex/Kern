#include "musig_psbt.h"

#include "bip32_path.h"
#include "descriptor_keys.h"
#include "key.h"
#include "psbt_internal.h"
#include "registry.h"
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_script.h>

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
