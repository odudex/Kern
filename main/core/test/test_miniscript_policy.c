/*
 * Tests for miniscript_policy: indenter (cases ported from Krux's
 * test_miniscript_indenter.py), key->letter substitution and recolor markup.
 *
 * Compile: see Makefile
 * Run: ./test_miniscript_policy
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#include "core/miniscript_policy.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
/* Uppercase hex, which libwally keeps as written in the canonical text */
#define XONLY_G_UPPER                                                          \
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define SHA256_UPPER                                                           \
  "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B85A"
#define SHA256_LOWER                                                           \
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85a"
#define HASH160_UPPER "E7D285B4817F83F724CD29394DA75DFC84FE639E"
#define HASH160_LOWER "e7d285b4817f83f724cd29394da75dfc84fe639e"

typedef struct {
  const char *input;
  const char *expected_25;
  const char *expected_27; /* NULL = same as expected_25 */
} indent_case_t;

/* Sipa's example scripts + others, from Krux test_miniscript_indenter.py */
static const indent_case_t INDENT_CASES[] = {
    {"pk(A)", "pk(\n A)", NULL},
    {"or_b(pk(A),s:pk(B))", "or_b(\n pk(A),\n s:pk(B))", NULL},
    {"or_d(pk(A),pkh(B))", "or_d(\n pk(A),\n pkh(B))", NULL},
    {"and_v(v:pk(A),or_d(pk(B),older(12960)))",
     "and_v(\n v:pk(A),\n or_d(\n  pk(B),\n  older(12960)))", NULL},
    {"thresh(3,pk(A),pk(B),pk(C),older(12960))",
     "thresh(\n 3,\n pk(A),\n pk(B),\n pk(C),\n older(12960))", NULL},
    {"andor(pk(A),older(1008),pk(B))",
     "andor(\n pk(A),\n older(1008),\n pk(B))", NULL},
    {"t:or_c(pk(A),and_v(v:pk(B),or_c(pk(C),v:hash160("
     "e7d285b4817f83f724cd29394da75dfc84fe639e))))",
     "t:or_c(\n pk(A),\n and_v(\n  v:pk(B),\n  or_c(\n   pk(C),\n   "
     "v:hash160(\n    e7d285b4817f83f724cd2\n    9394da75dfc84fe639e))\n    "
     "))",
     "t:or_c(\n pk(A),\n and_v(\n  v:pk(B),\n  or_c(\n   pk(C),\n   "
     "v:hash160(\n    e7d285b4817f83f724cd293\n    94da75dfc84fe639e))))"},
    {"andor(pk(A),or_i(and_v(v:pkh(B),hash160("
     "e7d285b4817f83f724cd29394da75dfc84fe639e)),older(1008)),pk(C))",
     "andor(\n pk(A),\n or_i(\n  and_v(\n   v:pkh(B),\n   hash160(\n    "
     "e7d285b4817f83f724cd2\n    9394da75dfc84fe639e))\n    ,\n  "
     "older(1008)),\n pk(C))",
     "andor(\n pk(A),\n or_i(\n  and_v(\n   v:pkh(B),\n   hash160(\n    "
     "e7d285b4817f83f724cd293\n    94da75dfc84fe639e)),\n  older(1008)),\n "
     "pk(C))"},
    {"or_d(pk(A),and_v(v:pkh(B),older(6)))",
     "or_d(\n pk(A),\n and_v(\n  v:pkh(B),\n  older(6)))", NULL},
    {"and_v(or_c(pk(B),or_c(pk(C),v:older(1000))),pk(A))",
     "and_v(\n or_c(\n  pk(B),\n  or_c(\n   pk(C),\n   v:older(1000))),\n "
     "pk(A))",
     NULL},
    {"or_d(multi(2,A,B),and_v(v:thresh(2,pkh(C),a:pkh(D),a:pkh(E)),"
     "older(144)))",
     "or_d(\n multi(2,A,B),\n and_v(\n  v:thresh(\n   2,\n   pkh(C),\n   "
     "a:pkh(D),\n   a:pkh(E)),\n  older(144)))",
     NULL},
    {"andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(230436)),thresh(2,"
     "pk(E),s:pk(F),s:pk(G),snl:after(230220))),and_v(v:thresh(2,pkh(H),"
     "a:pkh(I),a:pkh(J)),after(230775)))",
     "andor(\n multi(2,A,B,C),\n or_i(\n  and_v(\n   v:pkh(D),\n   "
     "after(230436)),\n  thresh(\n   2,\n   pk(E),\n   s:pk(F),\n   "
     "s:pk(G),\n   snl:after(230220))),\n and_v(\n  v:thresh(\n   2,\n   "
     "pkh(H),\n   a:pkh(I),\n   a:pkh(J)),\n  after(230775)))",
     NULL},
    {"andor(multi(2,A,B,C),or_i(and_v(v:pkh(D),after(1737233087)),thresh(2,"
     "pk(E),s:pk(F),s:pk(G),snl:after(1737146691))),and_v(v:thresh(2,pkh(H),"
     "a:pkh(I),a:pkh(J)),after(1737319495)))",
     "andor(\n multi(2,A,B,C),\n or_i(\n  and_v(\n   v:pkh(D),\n   "
     "after(1737233087)),\n  thresh(\n   2,\n   pk(E),\n   s:pk(F),\n   "
     "s:pk(G),\n   snl:after(1737146691))\n   ),\n and_v(\n  v:thresh(\n   "
     "2,\n   pkh(H),\n   a:pkh(I),\n   a:pkh(J)),\n  after(1737319495)))",
     "andor(\n multi(2,A,B,C),\n or_i(\n  and_v(\n   v:pkh(D),\n   "
     "after(1737233087)),\n  thresh(\n   2,\n   pk(E),\n   s:pk(F),\n   "
     "s:pk(G),\n   snl:after(1737146691))),\n and_v(\n  v:thresh(\n   2,\n   "
     "pkh(H),\n   a:pkh(I),\n   a:pkh(J)),\n  after(1737319495)))"},
    {"tr(A,and_v(v:pk(B),older(65535)))",
     "tr(\n A,\n and_v(\n  v:pk(B),\n  older(65535)))", NULL},
    {"tr(A,{and_v(v:multi_a(2,B,C,D),older(6)),multi_a(2,F,G)})",
     "tr(\n A,\n {and_v(\n  v:multi_a(2,B,C,D),\n  older(6)),\n "
     "multi_a(2,F,G)})",
     NULL},
};

static void check_indent(const char *input, size_t width,
                         const char *expected) {
  char name[64];
  snprintf(name, sizeof(name), "indent w%zu: %.40s", width, input);
  TEST(name);

  char *indented = miniscript_policy_indent(input, width);
  if (!indented) {
    FAIL("returned NULL");
    return;
  }
  if (strcmp(indented, expected) != 0) {
    printf("\n--- got ---\n%s\n--- expected ---\n%s\n", indented, expected);
    FAIL("mismatch");
    free(indented);
    return;
  }

  /* Roundtrip: stripping spaces and newlines reproduces the input. */
  char *stripped = malloc(strlen(indented) + 1);
  char *p = stripped;
  for (const char *s = indented; *s; s++)
    if (*s != ' ' && *s != '\n')
      *p++ = *s;
  *p = '\0';
  bool roundtrip = strcmp(stripped, input) == 0;
  free(stripped);
  free(indented);
  if (!roundtrip) {
    FAIL("roundtrip mismatch");
    return;
  }
  PASS();
}

static void test_indenter(void) {
  size_t n = sizeof(INDENT_CASES) / sizeof(INDENT_CASES[0]);
  for (size_t i = 0; i < n; i++) {
    const indent_case_t *c = &INDENT_CASES[i];
    check_indent(c->input, 25, c->expected_25);
    check_indent(c->input, 27,
                 c->expected_27 ? c->expected_27 : c->expected_25);
  }
}

static struct wally_descriptor *parse_desc(const char *str) {
  struct wally_descriptor *desc = NULL;
  if (wally_descriptor_parse(str, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0,
                             &desc) != WALLY_OK)
    return NULL;
  return desc;
}

static void check_policy_string(const char *name, const char *descriptor,
                                const char *expected) {
  TEST(name);
  struct wally_descriptor *desc = parse_desc(descriptor);
  if (!desc) {
    FAIL("descriptor parse failed");
    return;
  }
  char *policy = miniscript_policy_string(desc);
  wally_descriptor_free(desc);
  if (!policy) {
    FAIL("policy string is NULL");
    return;
  }
  if (strcmp(policy, expected) != 0) {
    printf("\n--- got ---\n%s\n--- expected ---\n%s\n", policy, expected);
    FAIL("mismatch");
  } else {
    PASS();
  }
  free(policy);
}

static void test_policy_string(void) {
  check_policy_string("policy string: origins + multipath",
                      "wsh(or_d(pk([00000000/48'/0'/0'/2']" XPUB_84 "/<0;1>/*),"
                      "and_v(v:pkh([11111111/48'/0'/0'/2']" XPUB_86
                      "/<0;1>/*),older(65535))))",
                      "wsh(or_d(pk(A),and_v(v:pkh(B),older(65535))))");

  check_policy_string("policy string: bare xpub key",
                      "wsh(and_v(v:pk(" XPUB_84 "/0/*),older(10)))",
                      "wsh(and_v(v:pk(A),older(10)))");

  check_policy_string("policy string: repeated key",
                      "wsh(or_d(pk([00000000/48'/0'/0'/2']" XPUB_84 "/0/*),"
                      "and_v(v:pkh([00000000/48'/0'/0'/2']" XPUB_84 "/2/*),"
                      "older(144))))",
                      "wsh(or_d(pk(A),and_v(v:pkh(A),older(144))))");
}

/* Only key letters may become KEY tokens, wherever the indenter breaks a
 * hash. */
static void check_key_tokens(const char *name, const char *descriptor,
                             const char *expected_keys) {
  TEST(name);
  struct wally_descriptor *desc = parse_desc(descriptor);
  char *policy = desc ? miniscript_policy_string(desc) : NULL;
  if (desc)
    wally_descriptor_free(desc);
  if (!policy) {
    FAIL("policy string is NULL");
    return;
  }
  bool ok = true;
  char keys[64] = "";
  for (size_t width = 10; ok && width <= 80; width++) {
    ms_policy_view_t view;
    if (!miniscript_policy_view_build(policy, width, &view)) {
      ok = false;
      break;
    }
    keys[0] = '\0';
    for (size_t i = 0; i < view.num_lines; i++)
      for (size_t j = 0; j < view.lines[i].num_tokens; j++)
        if (view.lines[i].tokens[j].kind == MS_TOKEN_KEY)
          strncat(keys, view.lines[i].tokens[j].text,
                  sizeof(keys) - strlen(keys) - 1);
    ok = strcmp(keys, expected_keys) == 0;
    miniscript_policy_view_free(&view);
  }
  free(policy);
  if (!ok) {
    printf("\n--- got keys '%s', expected '%s' ---\n", keys, expected_keys);
    FAIL("mismatch");
  } else {
    PASS();
  }
}

static void test_policy_case(void) {
  const char *hashlock = "wsh(and_v(v:pk([00000000/48'/0'/0'/2']" XPUB_84
                         "/<0;1>/*),sha256(" SHA256_UPPER ")))";
  check_policy_string("policy string: uppercase hash lowercased", hashlock,
                      "wsh(and_v(v:pk(A),sha256(" SHA256_LOWER ")))");
  check_key_tokens("view: hex digits never painted as keys", hashlock, "A");

  check_policy_string("policy string: uppercase raw key",
                      "wsh(and_v(v:pk(02" XONLY_G_UPPER "),older(10)))",
                      "wsh(and_v(v:pk(A),older(10)))");

  const char *tr_upper =
      "tr(" XONLY_G_UPPER ",and_v(v:pk([00000000/86'/0'/0']" XPUB_86
      "/0/*),hash160(" HASH160_UPPER ")))";
  check_policy_string("policy string: uppercase tr internal key and hash",
                      tr_upper,
                      "tr(A,and_v(v:pk(B),hash160(" HASH160_LOWER ")))");
  check_key_tokens("view: tr keys only", tr_upper, "AB");
}

#define XONLY_G                                                                \
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define XONLY_2G                                                               \
  "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

/* tr() keys are x-only in libwally but may be written compressed: the 02/03
 * prefix and any origin belong to the key expression. */
static void test_policy_compressed_tr_keys(void) {
  check_policy_string("policy string: compressed tr internal and leaf keys",
                      "tr(02" XONLY_G ",and_v(v:pk(03" XONLY_2G "),older(10)))",
                      "tr(A,and_v(v:pk(B),older(10)))");
  check_policy_string("policy string: compressed tr keys with origins",
                      "tr([00000000/86'/0'/0']02" XONLY_G
                      ",and_v(v:pk([11111111/86'/0'/0']03" XONLY_2G
                      "),older(10)))",
                      "tr(A,and_v(v:pk(B),older(10)))");
}

/* A hash argument equal to a later key's hex stays a hash. */
static void test_policy_hash_equal_to_key(void) {
  check_policy_string("policy string: hash equal to a later key stays a hash",
                      "tr(" XONLY_G ",and_v(v:sha256(" XONLY_2G "),pk(" XONLY_2G
                      ")))",
                      "tr(A,and_v(v:sha256(" XONLY_2G "),pk(B)))");
}

/* A flattened thresh() must carry each child whole, not just its first line. */
static void test_thresh_combinator_child(void) {
  check_key_tokens("view: thresh keeps the keys under an or_b child",
                   "wsh(thresh(2,pk(" XPUB_84 "/0/*),a:pk(" XPUB_84 "/1/*),"
                   "a:or_b(pk(" XPUB_84 "/2/*),a:pk(" XPUB_84 "/3/*))))",
                   "AAAA");
  check_key_tokens("view: thresh keeps the keys under an and_b child",
                   "wsh(thresh(1,pk(" XPUB_84 "/0/*),a:and_b(pk(" XPUB_84
                   "/1/*),a:pk(" XPUB_84 "/2/*))))",
                   "AAA");
}

static void test_is_miniscript(void) {
  TEST("is_miniscript: wsh(or_d) true, wsh(sortedmulti) false");
  struct wally_descriptor *ms =
      parse_desc("wsh(or_d(pk([00000000/48'/0'/0'/2']" XPUB_84 "/0/*),"
                 "and_v(v:pkh([11111111/48'/0'/0'/2']" XPUB_86 "/0/*),"
                 "older(65535))))");
  struct wally_descriptor *sm =
      parse_desc("wsh(sortedmulti(2,"
                 "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                 "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*))");
  if (!ms || !sm) {
    FAIL("descriptor parse failed");
  } else if (!miniscript_policy_is_miniscript(ms)) {
    FAIL("wsh(or_d) not detected as miniscript");
  } else if (miniscript_policy_is_miniscript(sm)) {
    FAIL("wsh(sortedmulti) detected as miniscript");
  } else {
    PASS();
  }
  if (ms)
    wally_descriptor_free(ms);
  if (sm)
    wally_descriptor_free(sm);

  /* A taptree of pk() leaves keeps WALLY_MS_IS_DESCRIPTOR set but is a
   * 1-of-N spend set, not a multisig; key-path-only tr() is single-sig. */
  TEST("is_miniscript: tr() pk-only tree true, tr(KEY) false");
  struct wally_descriptor *tree =
      parse_desc("tr([00000000/86'/0'/0']" XPUB_86 "/0/*,"
                 "{pk([11111111/86'/0'/0']" XPUB_84 "/0/*),"
                 "pkh([22222222/86'/0'/0']" XPUB_84 "/1/*)})");
  struct wally_descriptor *keypath =
      parse_desc("tr([00000000/86'/0'/0']" XPUB_86 "/0/*)");
  if (!tree || !keypath)
    FAIL("descriptor parse failed");
  else if (!miniscript_policy_is_miniscript(tree))
    FAIL("pk-only taptree not detected as miniscript");
  else if (miniscript_policy_is_miniscript(keypath))
    FAIL("key-path tr() detected as miniscript");
  else
    PASS();
  if (tree)
    wally_descriptor_free(tree);
  if (keypath)
    wally_descriptor_free(keypath);
}

typedef struct {
  ms_token_kind_t kind;
  const char *text;
} expected_token_t;

typedef struct {
  int level;
  const expected_token_t *tokens;
  size_t num_tokens;
} expected_line_t;

static void check_view(const char *name, const char *policy, size_t width,
                       const expected_line_t *expected, size_t num_expected) {
  TEST(name);
  ms_policy_view_t view;
  if (!miniscript_policy_view_build(policy, width, &view)) {
    FAIL("view build failed");
    return;
  }
  bool ok = (view.num_lines == num_expected);
  for (size_t i = 0; ok && i < num_expected; i++) {
    const ms_policy_line_t *line = &view.lines[i];
    const expected_line_t *exp = &expected[i];
    ok = (line->level == exp->level && line->num_tokens == exp->num_tokens);
    for (size_t j = 0; ok && j < exp->num_tokens; j++)
      ok = (line->tokens[j].kind == exp->tokens[j].kind &&
            strcmp(line->tokens[j].text, exp->tokens[j].text) == 0);
  }
  if (!ok) {
    printf("\n--- got ---\n");
    for (size_t i = 0; i < view.num_lines; i++) {
      printf("level %d:", view.lines[i].level);
      for (size_t j = 0; j < view.lines[i].num_tokens; j++)
        printf(" [%d]'%s'", view.lines[i].tokens[j].kind,
               view.lines[i].tokens[j].text);
      printf("\n");
    }
    FAIL("mismatch");
  } else {
    PASS();
  }
  miniscript_policy_view_free(&view);
}

static void test_view(void) {
  {
    static const expected_token_t l0[] = {{MS_TOKEN_PLUMBING, "wsh("}};
    static const expected_token_t l1[] = {{MS_TOKEN_OPERATOR, "or_d"},
                                          {MS_TOKEN_PLUMBING, "("}};
    static const expected_token_t l2[] = {{MS_TOKEN_TEXT, "pk"},
                                          {MS_TOKEN_PLUMBING, "("},
                                          {MS_TOKEN_KEY, "A"},
                                          {MS_TOKEN_PLUMBING, "),"}};
    static const expected_token_t l3[] = {{MS_TOKEN_OPERATOR, "and_v"},
                                          {MS_TOKEN_PLUMBING, "("}};
    static const expected_token_t l4[] = {{MS_TOKEN_PLUMBING, "v:"},
                                          {MS_TOKEN_TEXT, "pkh"},
                                          {MS_TOKEN_PLUMBING, "("},
                                          {MS_TOKEN_KEY, "B"},
                                          {MS_TOKEN_PLUMBING, "),"}};
    static const expected_token_t l5[] = {{MS_TOKEN_TIMELOCK, "older(6)"},
                                          {MS_TOKEN_NOTE, "~1 h"},
                                          {MS_TOKEN_PLUMBING, ")))"}};
    static const expected_line_t lines[] = {
        {0, l0, 1}, {1, l1, 2}, {2, l2, 4}, {2, l3, 2}, {3, l4, 5}, {3, l5, 3},
    };
    check_view("view: wsh(or_d(pk(A),and_v(v:pkh(B),older(6))))",
               "wsh(or_d(pk(A),and_v(v:pkh(B),older(6))))", 25, lines,
               sizeof(lines) / sizeof(lines[0]));
  }
  {
    // multi flattened on one line; snl: wrapper; after() unix timestamp date
    static const expected_token_t l0[] = {{MS_TOKEN_OPERATOR, "thresh"},
                                          {MS_TOKEN_PLUMBING, "("}};
    static const expected_token_t l1[] = {{MS_TOKEN_TEXT, "2"},
                                          {MS_TOKEN_PLUMBING, ","}};
    static const expected_token_t l2[] = {
        {MS_TOKEN_OPERATOR, "multi"}, {MS_TOKEN_PLUMBING, "("},
        {MS_TOKEN_TEXT, "2"},         {MS_TOKEN_PLUMBING, ","},
        {MS_TOKEN_KEY, "A"},          {MS_TOKEN_PLUMBING, ","},
        {MS_TOKEN_KEY, "B"},          {MS_TOKEN_PLUMBING, "),"}};
    static const expected_token_t l3[] = {
        {MS_TOKEN_PLUMBING, "snl:"},
        {MS_TOKEN_TIMELOCK, "after(1737233087)"},
        {MS_TOKEN_NOTE, "2025-01-18"},
        {MS_TOKEN_PLUMBING, ")"}};
    static const expected_line_t lines[] = {
        {0, l0, 2},
        {1, l1, 2},
        {1, l2, 8},
        {1, l3, 4},
    };
    check_view("view: thresh with multi and after() timestamp",
               "thresh(2,multi(2,A,B),snl:after(1737233087))", 25, lines,
               sizeof(lines) / sizeof(lines[0]));
  }
}

static void check_note(const char *name, const char *policy,
                       const char *expected_note) {
  TEST(name);
  ms_policy_view_t view;
  if (!miniscript_policy_view_build(policy, 50, &view)) {
    FAIL("view build failed");
    return;
  }
  const char *note = NULL;
  bool has_timelock = false;
  for (size_t i = 0; i < view.num_lines; i++)
    for (size_t j = 0; j < view.lines[i].num_tokens; j++) {
      if (view.lines[i].tokens[j].kind == MS_TOKEN_TIMELOCK)
        has_timelock = true;
      if (view.lines[i].tokens[j].kind == MS_TOKEN_NOTE)
        note = view.lines[i].tokens[j].text;
    }
  if (!has_timelock) {
    FAIL("no timelock token");
  } else if (!expected_note) {
    if (note) {
      printf("\n--- got note '%s', expected none ---\n", note);
      FAIL("unexpected note");
    } else {
      PASS();
    }
  } else if (!note || strcmp(note, expected_note) != 0) {
    printf("\n--- got note '%s', expected '%s' ---\n", note ? note : "(none)",
           expected_note);
    FAIL("note mismatch");
  } else {
    PASS();
  }
  miniscript_policy_view_free(&view);
}

static void test_timelock_notes(void) {
  check_note("note: older(6) ~1 h", "and_v(v:pk(A),older(6))", "~1 h");
  check_note("note: older(144) ~1 day", "and_v(v:pk(A),older(144))", "~1 day");
  check_note("note: older(65535) ~455 days", "and_v(v:pk(A),older(65535))",
             "~455 days");
  check_note("note: older(3) ~30 min", "and_v(v:pk(A),older(3))", "~30 min");
  // Time-based relative lock: bit 22 set, 14 * 512s = ~2 h
  check_note("note: older time-based ~2 h", "and_v(v:pk(A),older(4194318))",
             "~2 h");
  check_note("note: after() block height has no note",
             "and_v(v:pk(A),after(230775))", NULL);
  check_note("note: after() timestamp date", "and_v(v:pk(A),after(1737319495))",
             "2025-01-19");
}

int main(void) {
  if (wally_init(0) != WALLY_OK) {
    printf("wally_init failed\n");
    return 1;
  }

  printf("=== miniscript_policy tests ===\n\n");
  test_indenter();
  test_policy_string();
  test_policy_case();
  test_thresh_combinator_child();
  test_policy_compressed_tr_keys();
  test_policy_hash_equal_to_key();
  test_is_miniscript();
  test_view();
  test_timelock_notes();

  printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
  wally_cleanup(0);
  return tests_failed > 0 ? 1 : 0;
}
