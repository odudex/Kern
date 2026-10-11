#ifndef SP_PSBT_H
#define SP_PSBT_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <wally_psbt.h>

// BIP375 and BIP376 field types, held in libwally's unknowns maps
#define PSBT_GLOBAL_SP_ECDH_SHARE 0x07
#define PSBT_GLOBAL_SP_DLEQ 0x08
#define PSBT_OUT_SP_V0_INFO 0x09
#define PSBT_OUT_SP_V0_LABEL 0x0a
#define PSBT_IN_SP_ECDH_SHARE 0x1d
#define PSBT_IN_SP_DLEQ 0x1e
#define PSBT_IN_SP_SPEND_BIP32_DERIVATION 0x1f
#define PSBT_IN_SP_TWEAK 0x20

typedef enum {
  SP_PSBT_OK,
  SP_PSBT_ERR_FIELD,   // a silent payment field is malformed
  SP_PSBT_ERR_INPUT,   // an input breaks the BIP352 input rules
  SP_PSBT_ERR_SIGHASH, // an input asks for a sighash other than ALL
  SP_PSBT_ERR_FOREIGN, // an eligible input is not ours
  SP_PSBT_ERR_KEYS,    // the silent payment keys could not be derived
  SP_PSBT_ERR_CRYPTO,  // a share, proof or output key could not be made
  SP_PSBT_ERR_SCRIPT,  // a preset output script differs from the derived one
  SP_PSBT_ERR_PSBT,    // the completed PSBT fails strict validation
} sp_psbt_result_t;

// True if any output carries PSBT_OUT_SP_V0_INFO.
bool sp_psbt_has_outputs(const struct wally_psbt *psbt);

// True if the PSBT carries any BIP375 or BIP376 field. Such a PSBT holds no
// key origin to read a network from.
bool sp_psbt_has_fields(const struct wally_psbt *psbt);

// True if some output has no script and every such output carries
// PSBT_OUT_SP_V0_INFO: the scripts a BIP375 signer derives.
bool sp_psbt_outputs_pending(const struct wally_psbt *psbt);

// The scan and spend public keys of an output's PSBT_OUT_SP_V0_INFO. False
// when the output has none or it is malformed.
KERN_WARN_UNUSED_RESULT bool
sp_output_keys(const struct wally_psbt_output *output, unsigned char *scan_out,
               unsigned char *spend_out);

// BIP375 signer pass with the loaded seed's silent payment keys: writes the
// global ECDH share and DLEQ proof of every scan key, derives every silent
// payment output script and freezes the transaction. Every eligible input
// must be ours, its key proven against the script it spends. A share or proof
// already present must match ours. On success *psbt is replaced by its
// strictly re-parsed copy; on failure it is left untouched. A v0 PSBT with
// silent payment fields is refused.
KERN_WARN_UNUSED_RESULT sp_psbt_result_t
sp_psbt_complete(struct wally_psbt **psbt, bool is_testnet);

// True when input `i` spends one of our silent payment outputs: its
// PSBT_IN_SP_TWEAK added to our spend key reproduces its P2TR output key.
bool sp_psbt_input_is_ours(const struct wally_psbt *psbt, size_t i,
                           bool is_testnet);

typedef enum {
  SP_OUTPUT_FOREIGN, // not ours, or not a silent payment output
  SP_OUTPUT_CHANGE,  // our scan key, our spend key labeled m = 0
  SP_OUTPUT_SELF,    // our scan key, our spend key unlabeled or labeled m > 0
} sp_output_ownership_t;

// Whose silent payment output `i` is. PSBT_OUT_SP_V0_LABEL, when present, must
// label our spend key into the output's one; without it, the change label
// and the unlabeled key are tried.
sp_output_ownership_t sp_psbt_output_ownership(const struct wally_psbt *psbt,
                                               size_t i, bool is_testnet);

// Key path signature of our silent payment input `i`, made with the tweaked
// spend key and no taproot tweak, since the output key already is BIP352's.
KERN_WARN_UNUSED_RESULT bool sp_psbt_sign_input(struct wally_psbt *psbt,
                                                size_t i, bool is_testnet);

// Copies the BIP375 global and output fields of `from` into its trimmed copy
// `to`, and writes TX_MODIFIABLE explicitly once frozen: bwk's verify_signed
// wants the field present, while libwally leaves out a zero one.
KERN_WARN_UNUSED_RESULT bool sp_psbt_copy_fields(const struct wally_psbt *from,
                                                 struct wally_psbt *to);

const char *sp_psbt_result_message(sp_psbt_result_t result);

#endif // SP_PSBT_H
