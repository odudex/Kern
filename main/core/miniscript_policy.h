#ifndef MINISCRIPT_POLICY_H
#define MINISCRIPT_POLICY_H

#include <stdbool.h>
#include <stddef.h>

struct wally_descriptor;

/* Keys are labeled with one letter ID each, 'A'..'Z'. Shared by the policy
 * letter substitution and every screen that lists descriptor keys. */
#define MINISCRIPT_POLICY_MAX_KEYS 26

bool miniscript_policy_is_miniscript(const struct wally_descriptor *desc);

/* Canonical descriptor with each key expression (origin, xpub and child
 * path) replaced by its letter ID ('A' + key index, matching the order keys
 * are listed by libwally). Returns a malloc'd string, e.g.
 * "wsh(or_d(pk(A),and_v(v:pkh(B),older(65535))))", or NULL on failure. */
char *miniscript_policy_string(const struct wally_descriptor *desc);

/* Indent a miniscript expression for display, one level per leading space,
 * breaking lines longer than max_line_width characters. Returns a malloc'd
 * '\n'-joined string, or NULL on failure. */
char *miniscript_policy_indent(const char *expr, size_t max_line_width);

typedef enum {
  MS_TOKEN_TEXT,     // fragment names (pk, pkh, hashes), numbers
  MS_TOKEN_PLUMBING, // script wrappers (wsh), type prefixes (v:), parens
  MS_TOKEN_OPERATOR, // logic fragments: or_*, and_*, andor, thresh, multi...
  MS_TOKEN_KEY,      // single-letter key ID
  MS_TOKEN_TIMELOCK, // full older(N) / after(N) fragment
  MS_TOKEN_NOTE,     // generated human-readable timelock annotation
} ms_token_kind_t;

typedef struct {
  ms_token_kind_t kind;
  char *text;
} ms_token_t;

typedef struct {
  int level; // indentation depth
  ms_token_t *tokens;
  size_t num_tokens;
} ms_policy_line_t;

typedef struct {
  ms_policy_line_t *lines;
  size_t num_lines;
} ms_policy_view_t;

/* Indent `policy` (see miniscript_policy_indent) and split it into lines of
 * classified tokens for styled rendering. Timelocks get a NOTE token with an
 * approximate duration (older) or UTC date (after, when it is a timestamp).
 * Free with miniscript_policy_view_free. */
bool miniscript_policy_view_build(const char *policy, size_t max_line_width,
                                  ms_policy_view_t *view);
void miniscript_policy_view_free(ms_policy_view_t *view);

#endif // MINISCRIPT_POLICY_H
