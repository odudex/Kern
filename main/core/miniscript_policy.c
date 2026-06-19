// Miniscript policy display helpers: key-expression -> letter substitution
// and an indented tree rendering ported from Krux's MiniScriptIndenter.

#include "miniscript_policy.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_descriptor.h>

bool miniscript_policy_is_miniscript(const struct wally_descriptor *desc) {
  uint32_t features = 0;
  if (wally_descriptor_get_features(desc, &features) != WALLY_OK)
    return false;
  return (features & WALLY_MS_IS_DESCRIPTOR) == 0;
}

char *miniscript_policy_string(const struct wally_descriptor *desc) {
  char *canon = NULL;
  if (wally_descriptor_canonicalize(desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canon) != WALLY_OK ||
      !canon)
    return NULL;

  uint32_t num_keys = 0;
  if (wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK ||
      num_keys == 0 || num_keys > MINISCRIPT_POLICY_MAX_KEYS) {
    wally_free_string(canon);
    return NULL;
  }

  // Replacements only shrink the string.
  char *out = malloc(strlen(canon) + 1);
  if (!out) {
    wally_free_string(canon);
    return NULL;
  }

  const char *src = canon;
  char *dst = out;
  bool ok = true;
  for (uint32_t i = 0; i < num_keys && ok; i++) {
    char *key_str = NULL;
    if (wally_descriptor_get_key(desc, i, &key_str) != WALLY_OK || !key_str) {
      ok = false;
      break;
    }
    const char *hit = strstr(src, key_str);
    if (!hit) {
      ok = false;
    } else {
      // Include a preceding [origin] block in the replacement.
      const char *start = hit;
      if (start > src && start[-1] == ']') {
        const char *lb = start - 1;
        while (lb > src && *lb != '[')
          lb--;
        if (*lb == '[')
          start = lb;
      }
      memcpy(dst, src, (size_t)(start - src));
      dst += start - src;
      *dst++ = (char)('A' + i);
      // Skip the trailing derivation suffix (/<0;1>/* etc).
      const char *end = hit + strlen(key_str);
      while (*end && strchr("/0123456789h'*<;>", *end))
        end++;
      src = end;
    }
    wally_free_string(key_str);
  }

  if (ok) {
    strcpy(dst, src);
  } else {
    free(out);
    out = NULL;
  }
  wally_free_string(canon);
  return out;
}

// ---------------------------------------------------------------------------
// Indenter (port of Krux MiniScriptIndenter)
// ---------------------------------------------------------------------------

typedef struct ms_node {
  char *text; // prefix before '(' or full leaf text
  struct ms_node **children;
  size_t num_children;
  int level;
} ms_node_t;

typedef struct {
  char **items;
  size_t count;
  size_t cap;
} lines_t;

static char *str_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (len < 0)
    return NULL;
  char *out = malloc((size_t)len + 1);
  if (!out)
    return NULL;
  va_start(ap, fmt);
  vsnprintf(out, (size_t)len + 1, fmt, ap);
  va_end(ap);
  return out;
}

static bool lines_push(lines_t *l, char *line) {
  if (!line)
    return false;
  if (l->count == l->cap) {
    size_t cap = l->cap ? l->cap * 2 : 8;
    char **items = realloc(l->items, cap * sizeof(*items));
    if (!items) {
      free(line);
      return false;
    }
    l->items = items;
    l->cap = cap;
  }
  l->items[l->count++] = line;
  return true;
}

static void lines_free(lines_t *l) {
  for (size_t i = 0; i < l->count; i++)
    free(l->items[i]);
  free(l->items);
  memset(l, 0, sizeof(*l));
}

static char *dup_trim(const char *s, size_t len) {
  while (len && *s == ' ') {
    s++;
    len--;
  }
  while (len && s[len - 1] == ' ')
    len--;
  char *out = malloc(len + 1);
  if (!out)
    return NULL;
  memcpy(out, s, len);
  out[len] = '\0';
  return out;
}

static void node_free(ms_node_t *node) {
  if (!node)
    return;
  for (size_t i = 0; i < node->num_children; i++)
    node_free(node->children[i]);
  free(node->children);
  free(node->text);
  free(node);
}

static bool node_add_child(ms_node_t *node, ms_node_t *child) {
  if (!child)
    return false;
  ms_node_t **children =
      realloc(node->children, (node->num_children + 1) * sizeof(*children));
  if (!children) {
    node_free(child);
    return false;
  }
  node->children = children;
  node->children[node->num_children++] = child;
  return true;
}

static ms_node_t *parse_expr(const char *expr, size_t len, int level) {
  while (len && *expr == ' ') {
    expr++;
    len--;
  }
  while (len && expr[len - 1] == ' ')
    len--;

  ms_node_t *node = calloc(1, sizeof(*node));
  if (!node)
    return NULL;
  node->level = level;

  const char *paren = memchr(expr, '(', len);
  if (!paren) {
    node->text = dup_trim(expr, len);
    if (!node->text) {
      node_free(node);
      return NULL;
    }
    return node;
  }

  size_t pos = (size_t)(paren - expr);
  node->text = dup_trim(expr, pos);
  if (!node->text || len < pos + 2) {
    node_free(node);
    return NULL;
  }

  // Children: inside the outermost parens, split at top-level commas.
  const char *inside = expr + pos + 1;
  size_t inside_len = len - pos - 2;
  int depth = 0;
  size_t start = 0;
  for (size_t i = 0; i < inside_len; i++) {
    char c = inside[i];
    if (c == '(') {
      depth++;
    } else if (c == ')') {
      depth--;
    } else if (c == ',' && depth == 0) {
      if (!node_add_child(node,
                          parse_expr(inside + start, i - start, level + 1))) {
        node_free(node);
        return NULL;
      }
      start = i + 1;
    }
  }
  if (start < inside_len &&
      !node_add_child(
          node, parse_expr(inside + start, inside_len - start, level + 1))) {
    node_free(node);
    return NULL;
  }
  return node;
}

// Merge lines that are only closing parens into the previous line.
static void join_closing_parens(lines_t *l) {
  for (size_t i = l->count - 1; i > 0; i--) {
    const char *s = l->items[i];
    while (*s == ' ')
      s++;
    if (!*s)
      continue;
    const char *p = s;
    while (*p == ')')
      p++;
    if (*p)
      continue;
    char *merged = str_printf("%s%s", l->items[i - 1], s);
    if (!merged)
      continue;
    free(l->items[i - 1]);
    l->items[i - 1] = merged;
    free(l->items[i]);
    memmove(&l->items[i], &l->items[i + 1],
            (l->count - i - 1) * sizeof(*l->items));
    l->count--;
  }
}

static bool node_to_lines(const ms_node_t *node, size_t max_width,
                          lines_t *out);

// First rendered line of a node, stripped of indentation.
static char *node_first_line(const ms_node_t *node, size_t max_width) {
  lines_t tmp = {0};
  if (!node_to_lines(node, max_width, &tmp)) {
    lines_free(&tmp);
    return NULL;
  }
  char *first = dup_trim(tmp.items[0], strlen(tmp.items[0]));
  lines_free(&tmp);
  return first;
}

static bool node_to_lines(const ms_node_t *node, size_t max_width,
                          lines_t *out) {
  if (node->num_children == 0)
    return lines_push(out, str_printf("%*s%s", node->level, "", node->text));

  // If any child is a leaf, try flattening all children onto one line.
  bool any_leaf = false;
  for (size_t i = 0; i < node->num_children; i++)
    if (node->children[i]->num_children == 0)
      any_leaf = true;
  if (any_leaf && node->level > 0) {
    char *line = str_printf("%*s%s(", node->level, "", node->text);
    for (size_t i = 0; line && i < node->num_children; i++) {
      char *child = node_first_line(node->children[i], max_width);
      char *next =
          child ? str_printf("%s%s%s", line, i ? "," : "", child) : NULL;
      free(child);
      free(line);
      line = next;
    }
    if (!line)
      return false;
    char *flat = str_printf("%s)", line);
    free(line);
    if (!flat)
      return false;
    if (strlen(flat) <= max_width)
      return lines_push(out, flat);
    free(flat);
  }

  if (!lines_push(out, str_printf("%*s%s(", node->level, "", node->text)))
    return false;
  for (size_t i = 0; i < node->num_children; i++) {
    if (!node_to_lines(node->children[i], max_width, out))
      return false;
    if (i < node->num_children - 1) {
      char *with_comma = str_printf("%s,", out->items[out->count - 1]);
      if (!with_comma)
        return false;
      free(out->items[out->count - 1]);
      out->items[out->count - 1] = with_comma;
    }
  }
  if (!lines_push(out, str_printf("%*s)", node->level, "")))
    return false;

  join_closing_parens(out);
  return true;
}

static void break_line_into(lines_t *out, const char *line, size_t max_width) {
  size_t len = strlen(line);
  if (len <= max_width) {
    lines_push(out, str_printf("%s", line));
    return;
  }
  size_t indent = 0;
  while (line[indent] == ' ')
    indent++;
  size_t chunk = (max_width > indent) ? max_width - indent : 1;
  const char *data = line + indent;
  size_t dlen = len - indent;
  while (dlen > chunk) {
    lines_push(out, str_printf("%*s%.*s", (int)indent, "", (int)chunk, data));
    data += chunk;
    dlen -= chunk;
  }
  lines_push(out, str_printf("%*s%.*s", (int)indent, "", (int)dlen, data));
}

char *miniscript_policy_indent(const char *expr, size_t max_line_width) {
  if (!expr || !*expr || max_line_width == 0)
    return NULL;

  bool multiple_tap_scripts = strchr(expr, '{') != NULL;

  ms_node_t *tree = parse_expr(expr, strlen(expr), 0);
  if (!tree)
    return NULL;
  lines_t raw = {0};
  bool ok = node_to_lines(tree, max_line_width, &raw);
  node_free(tree);
  if (!ok || raw.count == 0) {
    lines_free(&raw);
    return NULL;
  }

  lines_t fin = {0};
  for (size_t i = 0; i < raw.count; i++)
    break_line_into(&fin, raw.items[i], max_line_width);
  lines_free(&raw);
  if (fin.count == 0) {
    lines_free(&fin);
    return NULL;
  }

  if (multiple_tap_scripts) {
    // Replace the penultimate ')' of the last line by '}'.
    char *last = fin.items[fin.count - 1];
    size_t len = strlen(last);
    if (len >= 2)
      last[len - 2] = '}';
  }

  size_t total = 0;
  for (size_t i = 0; i < fin.count; i++)
    total += strlen(fin.items[i]) + 1;
  char *joined = malloc(total);
  if (joined) {
    char *p = joined;
    for (size_t i = 0; i < fin.count; i++) {
      size_t len = strlen(fin.items[i]);
      memcpy(p, fin.items[i], len);
      p += len;
      *p++ = (i < fin.count - 1) ? '\n' : '\0';
    }
  }
  lines_free(&fin);
  return joined;
}

// ---------------------------------------------------------------------------
// Token view
// ---------------------------------------------------------------------------

static bool is_operator_fragment(const char *name, size_t len) {
  static const char *const OPS[] = {
      "or_b",        "or_c",    "or_d",          "or_i",   "and_v",
      "and_b",       "and_n",   "andor",         "thresh", "multi",
      "sortedmulti", "multi_a", "sortedmulti_a",
  };
  for (size_t i = 0; i < sizeof(OPS) / sizeof(OPS[0]); i++)
    if (strlen(OPS[i]) == len && memcmp(OPS[i], name, len) == 0)
      return true;
  return false;
}

static bool is_wrapper_fragment(const char *name, size_t len) {
  static const char *const WRAPPERS[] = {"wsh", "sh", "tr"};
  for (size_t i = 0; i < sizeof(WRAPPERS) / sizeof(WRAPPERS[0]); i++)
    if (strlen(WRAPPERS[i]) == len && memcmp(WRAPPERS[i], name, len) == 0)
      return true;
  return false;
}

// "~N min" / "~N h" / "~N day(s)" for an older() relative locktime.
static bool format_older_note(uint32_t n, char *out, size_t out_size) {
  if (n == 0 || n >= 0x80000000u)
    return false;
  uint32_t secs;
  if (n & 0x00400000u)
    secs = (n & 0xFFFFu) * 512u; // time-based lock, 512s units
  else
    secs = n * 600u; // block-based lock, ~10 min per block
  if (secs < 3600u) {
    snprintf(out, out_size, "~%u min", (secs + 30u) / 60u);
  } else if (secs < 24u * 3600u) {
    snprintf(out, out_size, "~%u h", (secs + 1800u) / 3600u);
  } else {
    uint32_t days = (secs + 43200u) / 86400u;
    snprintf(out, out_size, "~%u day%s", days, days == 1 ? "" : "s");
  }
  return true;
}

// "YYYY-MM-DD" (UTC) for an after() absolute locktime, when it is a unix
// timestamp. Block heights (< 500000000) get no note.
static bool format_after_note(uint32_t n, char *out, size_t out_size) {
  if (n < 500000000u)
    return false;
  // Civil-from-days (Howard Hinnant), all integer math.
  int64_t z = (int64_t)(n / 86400u) + 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  uint32_t doe = (uint32_t)(z - era * 146097);
  uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = (int64_t)yoe + era * 400;
  uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  uint32_t mp = (5 * doy + 2) / 153;
  uint32_t d = doy - (153 * mp + 2) / 5 + 1;
  uint32_t m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2)
    y++;
  snprintf(out, out_size, "%lld-%02u-%02u", (long long)y, m, d);
  return true;
}

typedef struct {
  ms_token_t *items;
  size_t count;
  size_t cap;
} tokens_t;

static bool tokens_push(tokens_t *t, ms_token_kind_t kind, const char *text,
                        size_t len) {
  // Merge into the previous token when the kind matches.
  if (t->count && t->items[t->count - 1].kind == kind &&
      kind != MS_TOKEN_NOTE) {
    ms_token_t *prev = &t->items[t->count - 1];
    size_t prev_len = strlen(prev->text);
    char *merged = realloc(prev->text, prev_len + len + 1);
    if (!merged)
      return false;
    memcpy(merged + prev_len, text, len);
    merged[prev_len + len] = '\0';
    prev->text = merged;
    return true;
  }
  if (t->count == t->cap) {
    size_t cap = t->cap ? t->cap * 2 : 8;
    ms_token_t *items = realloc(t->items, cap * sizeof(*items));
    if (!items)
      return false;
    t->items = items;
    t->cap = cap;
  }
  char *copy = malloc(len + 1);
  if (!copy)
    return false;
  memcpy(copy, text, len);
  copy[len] = '\0';
  t->items[t->count].kind = kind;
  t->items[t->count].text = copy;
  t->count++;
  return true;
}

static void tokens_destroy(tokens_t *t) {
  for (size_t i = 0; i < t->count; i++)
    free(t->items[i].text);
  free(t->items);
  memset(t, 0, sizeof(*t));
}

static bool is_ident_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static bool tokenize_line(const char *s, tokens_t *out) {
  size_t i = 0;
  while (s[i]) {
    char c = s[i];

    if (c == '(' || c == ')' || c == ',' || c == '{' || c == '}') {
      size_t start = i;
      while (s[i] == '(' || s[i] == ')' || s[i] == ',' || s[i] == '{' ||
             s[i] == '}')
        i++;
      if (!tokens_push(out, MS_TOKEN_PLUMBING, s + start, i - start))
        return false;
      continue;
    }

    if (c >= 'A' && c <= 'Z' &&
        (s[i + 1] == ')' || s[i + 1] == ',' || s[i + 1] == '\0')) {
      if (!tokens_push(out, MS_TOKEN_KEY, s + i, 1))
        return false;
      i++;
      continue;
    }

    if (c >= 'a' && c <= 'z') {
      size_t start = i;
      while (is_ident_char(s[i]))
        i++;
      size_t len = i - start;
      if (s[i] == ':') { // type-coercion wrapper prefix (v:, snl:, ...)
        i++;
        if (!tokens_push(out, MS_TOKEN_PLUMBING, s + start, i - start))
          return false;
        continue;
      }
      bool is_timelock = (len == 5 && (memcmp(s + start, "older", 5) == 0 ||
                                       memcmp(s + start, "after", 5) == 0));
      if (is_timelock && s[i] == '(') {
        // Take the whole "older(N)" fragment when it is unbroken.
        size_t j = i + 1, num_start = i + 1;
        while (s[j] >= '0' && s[j] <= '9')
          j++;
        if (j > num_start && s[j] == ')') {
          unsigned long n = strtoul(s + num_start, NULL, 10);
          if (!tokens_push(out, MS_TOKEN_TIMELOCK, s + start, j + 1 - start))
            return false;
          char note[24];
          bool has_note =
              (s[start] == 'o')
                  ? format_older_note((uint32_t)n, note, sizeof(note))
                  : format_after_note((uint32_t)n, note, sizeof(note));
          if (has_note && !tokens_push(out, MS_TOKEN_NOTE, note, strlen(note)))
            return false;
          i = j + 1;
          continue;
        }
      }
      ms_token_kind_t kind = MS_TOKEN_TEXT;
      if (is_timelock)
        kind = MS_TOKEN_TIMELOCK; // fragment split across lines
      else if (is_operator_fragment(s + start, len))
        kind = MS_TOKEN_OPERATOR;
      else if (is_wrapper_fragment(s + start, len))
        kind = MS_TOKEN_PLUMBING;
      if (!tokens_push(out, kind, s + start, len))
        return false;
      continue;
    }

    size_t start = i++;
    if (!tokens_push(out, MS_TOKEN_TEXT, s + start, i - start))
      return false;
  }
  return true;
}

bool miniscript_policy_view_build(const char *policy, size_t max_line_width,
                                  ms_policy_view_t *view) {
  if (!view)
    return false;
  memset(view, 0, sizeof(*view));

  char *indented = miniscript_policy_indent(policy, max_line_width);
  if (!indented)
    return false;

  size_t num_lines = 1;
  for (const char *p = indented; *p; p++)
    if (*p == '\n')
      num_lines++;
  view->lines = calloc(num_lines, sizeof(*view->lines));
  if (!view->lines) {
    free(indented);
    return false;
  }

  bool ok = true;
  char *line = indented;
  while (ok && line) {
    char *next = strchr(line, '\n');
    if (next)
      *next++ = '\0';

    int level = 0;
    while (line[level] == ' ')
      level++;

    tokens_t tokens = {0};
    ok = tokenize_line(line + level, &tokens);
    if (ok) {
      ms_policy_line_t *out = &view->lines[view->num_lines++];
      out->level = level;
      out->tokens = tokens.items;
      out->num_tokens = tokens.count;
    } else {
      tokens_destroy(&tokens);
    }
    line = next;
  }
  free(indented);

  if (!ok)
    miniscript_policy_view_free(view);
  return ok;
}

void miniscript_policy_view_free(ms_policy_view_t *view) {
  if (!view)
    return;
  for (size_t i = 0; i < view->num_lines; i++) {
    for (size_t j = 0; j < view->lines[i].num_tokens; j++)
      free(view->lines[i].tokens[j].text);
    free(view->lines[i].tokens);
  }
  free(view->lines);
  memset(view, 0, sizeof(*view));
}
