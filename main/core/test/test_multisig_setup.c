/*
 * Multisig setup file tests (core/multisig_setup.c).
 *
 * The Sparrow and Nunchuk files are real exports (see
 * components/bbqr/test/bbqr_samples.h). OWN_* keys come from the BIP39 test
 * mnemonic (fingerprint 73c5da0a), COS_* keys from "zoo ... wrong"
 * (3f635a63); the SLIP-132 forms only swap the version bytes.
 *
 * Compile: see Makefile
 * Run: ./test_multisig_setup
 */

#include "../multisig_setup.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_failed = 0;

static void expect(const char *name, const char *text, const char *want) {
  char *got = multisig_setup_to_descriptor(text);
  bool ok = want ? got && strcmp(got, want) == 0 : !got;
  tests_run++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
  if (!ok) {
    tests_failed++;
    printf("  got:  %s\n  want: %s\n", got ? got : "(null)",
           want ? want : "(null)");
  }
  free(got);
}

/* m/48'/1'/0'/2' keys of the Sparrow and Nunchuk exports */
#define TP_65FB                                                                \
  "tpubDFM6mziafLfJPA9StFuzvdC5htjaMTsVaPSAjsahgE4c2CMWpg9yKaK4JyoaBjVYJKUFX9" \
  "Kdyb4fgFaFUQmZNGU71Q1wZgZiGM1Go7p59NW"
#define TP_473C                                                                \
  "tpubDEUCuxkfzMNmTG7oprJfK1HBHu3FNM43DMymAjyuwXNMNx4WwLib7xSacz5zMKRDcABJc2" \
  "oezBLiefLarPuoXCnbTJmpuwodbP4nRoURJdS"
#define TP_84B9                                                                \
  "tpubDE6D5hG2QULH8XcBwZRP81DjFEYhkdRdE5EdAJXctPk6cCWJozhr6FaSyoopyU9DcUiKnU" \
  "rZ14gZcdLRuSaTwDPpynBzdfmt4FEmenYTfrt"

/* m/48'/0'/0'/2' */
#define OWN_0                                                                  \
  "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcb" \
  "XFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf"
#define OWN_0_ZPUB                                                             \
  "Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8" \
  "iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG"
/* m/48'/0'/1'/2' */
#define OWN_1                                                                  \
  "xpub6DzhyrnFFYQ1HimDiM388xHnDiRPNdZJFBmmxge3Y1WWcHLtMJLfRuhRHqnQCPbTj3fGKT" \
  "uKFLHzzwpJkp5Dtc3UtLKZKaVZe1yqMBXd6Vk"
/* m/48'/0'/0'/1' */
#define OWN_SH                                                                 \
  "xpub6DkFAXWQ2dHxnMKoSBogHrw1rgNJKR4umdbnNVNTYeCGcduxWnNUHgGptqEQWPKRmeW4Zn" \
  "4FHSbLMBKEWYaMDYu47Ytg6DdFnPNt8hwn5mE"
#define OWN_SH_YPUB                                                            \
  "Ypub6jUbbRukkGPp4DgJDD4HL2NKkSZ1UPk111mg59XtJRQZHvJ6XqvJzrntik9U4jCFQkgrBq" \
  "evdKLPMdYZXU9KAGhKpMhW5XujwqiQ7Csmm4Z"
/* m/48'/1'/0'/2' and m/48'/1'/0'/1' */
#define OWN_T2                                                                 \
  "tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbv" \
  "EW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ"
#define OWN_T2_VPUB                                                            \
  "vpub5bEzW7qQeLAj252JMMM1EBEqJZzP62DuzmqnPxKVGDSQj4mZWwPct6oiyQD6rXiVrJVoVP" \
  "XWceMjTdjaCE8B7HNWb2Pyrr5Wp3cLtPpRDHp"
#define OWN_T1                                                                 \
  "tpubDFH9dgzveyD8yHQb8VrpG8FYAuwcLMHMje2CCcbBo1FpaGzYVtJeYYxcYgRqSTta5utUFt" \
  "s8nPPHs9C2bqoxrey5jia6Dwf9mpwrPq7YvcJ"
#define OWN_T2_VPUB_MS                                                         \
  "Vpub5n95dMZrDHj6SeBgJ1oz4Fae2N2eJNuWK3VTKDb2dzGpMFLUHLmtyDfen7AaQxwQ5mZnMy" \
  "XdVrkEaoMLVTH8FmVBRVWPGFYWhmtDUGehGmq"
#define OWN_T1_UPUB_MS                                                         \
  "Upub5TJpKgtw4cBcaAom7tyqG1yU3gSsjTVPkwWuR97vgrChHsT4S6M9d3BJ3jRmUgCUJZ58GU" \
  "ZhkWt6eGUVM7sdizaeuZqvC61TGRSP43VHvGm"
#define OWN_T1_UPUB                                                            \
  "upub5GQjCTAVVedF9bePBEWrRwdfKtQcX6ooSfsEVsrPK5NHfgt9fgxsXvKNF2UHvEya5619Pt" \
  "ZasJVbX6rj3tigaWTz56jWngYTNhAWU7wjLPa"

/* m/48'/0'/0'/2' */
#define COS                                                                    \
  "xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz" \
  "8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr"
#define COS_ZPUB                                                               \
  "Zpub75rAwNSrvDKNvAomunzgBvnBJs6VXV8LAmNrjAqPzjaygZtqWLxuuNoBQYAVY8hjNJpThX" \
  "KKpei18636Q34ExQPyYg9wQwxo7PsgR4puq6J"
/* m/48'/0'/0'/1' */
#define COS_SH                                                                 \
  "xpub6FHZCoNb3tg3mxjcXsQx1xLpNmod6woECf2fB4nQbe9NXbvha2ucpDpnGbTFF68KUMUr1h" \
  "NQ9E5jVEvpT2kUkVmFVDrJawcbgXzDpJc2hkF"
#define COS_SH_YPUB                                                            \
  "Ypub6m1udhmwmXmu3q67JtfZ47n8GXzLFvUKS3CYsiwqMRMfCtJqb6TTXQLr6WNJoS197Tfddk" \
  "y5V6pnVhA9TxKShDZXC2f8aFu5qzKjnp1svff"

#define O0 "[73c5da0a/48'/0'/0'/2']"
#define O1 "[73c5da0a/48'/0'/1'/2']"
#define C0 "[3f635a63/48'/0'/0'/2']"

/* Two of the wallet's own accounts plus a cosigner */
#define TWO_ACCOUNTS "wsh(sortedmulti(2," O0 OWN_0 "," O1 OWN_1 "," C0 COS "))"

static void test_single_header(void) {
  const char *sparrow = "# Coldcard Multisig setup file (created by Sparrow)\n"
                        "#\n"
                        "Name: multisig\n"
                        "Policy: 2 of 3\n"
                        "Derivation: m/48'/1'/0'/2'\n"
                        "Format: P2WSH\n"
                        "\n"
                        "65FB43FE: " TP_65FB "\n"
                        "473C5C27: " TP_473C "\n"
                        "84B90E2B: " TP_84B9 "\n";
  expect("Sparrow export with one Derivation header", sparrow,
         "wsh(sortedmulti(2,[65fb43fe/48'/1'/0'/2']" TP_65FB
         ",[473c5c27/48'/1'/0'/2']" TP_473C ",[84b90e2b/48'/1'/0'/2']" TP_84B9
         "))");

  const char *nunchuk = "# Exported from Nunchuk\n"
                        "Name: multisig\n"
                        "Policy: 2 of 3\n"
                        "Format: P2WSH\n"
                        "\n"
                        "Derivation: m/48'/1'/0'/2'\n"
                        "65fb43fe: " TP_65FB "\n"
                        "\n"
                        "Derivation: m/48'/1'/0'/2'\n"
                        "84b90e2b: " TP_84B9 "\n"
                        "\n"
                        "Derivation: m/48'/1'/0'/2'\n"
                        "473c5c27: " TP_473C "\n"
                        "\n";
  expect("Nunchuk export repeating one path per key", nunchuk,
         "wsh(sortedmulti(2,[65fb43fe/48'/1'/0'/2']" TP_65FB
         ",[84b90e2b/48'/1'/0'/2']" TP_84B9 ",[473c5c27/48'/1'/0'/2']" TP_473C
         "))");
}

static void test_per_key_derivation(void) {
  const char *sparrow = "# Coldcard Multisig setup file (created by Sparrow)\n"
                        "#\n"
                        "Name: two-accounts\n"
                        "Policy: 2 of 3\n"
                        "Format: P2WSH\n"
                        "\n"
                        "Derivation: m/48'/0'/0'/2'\n"
                        "73C5DA0A: " OWN_0 "\n"
                        "\n"
                        "Derivation: m/48'/0'/1'/2'\n"
                        "73C5DA0A: " OWN_1 "\n"
                        "\n"
                        "Derivation: m/48'/0'/0'/2'\n"
                        "3F635A63: " COS "\n"
                        "\n";
  expect("Derivation line before each key", sparrow, TWO_ACCOUNTS);

  const char *coldcard =
      "# Coldcard Multisig setup file (exported from unknown)\n"
      "#\n"
      "Name: two-accounts\n"
      "Policy: 2 of 3\n"
      "Format: P2WSH\n"
      "\n"
      "Derivation: m/48'/0'/0'/2'\n"
      "\n"
      "73C5DA0A: " OWN_0 "\n"
      "3F635A63: " COS "\n"
      "\n"
      "Derivation: m/48'/0'/1'/2'\n"
      "\n"
      "73C5DA0A: " OWN_1 "\n";
  expect("Derivation line only where the path changes", coldcard,
         "wsh(sortedmulti(2," O0 OWN_0 "," C0 COS "," O1 OWN_1 "))");

  const char *crlf = "Name: two-accounts\r\n"
                     "Policy: 2 of 3\r\n"
                     "Format: P2WSH\r\n"
                     "\r\n"
                     "  Derivation: m/48'/0'/0'/2'\r\n"
                     "  73c5da0a: " OWN_0 "\r\n"
                     "\tDerivation:48'/0'/1'/2'\r\n"
                     "\t73c5da0a: " OWN_1 "\r\n"
                     "Derivation: m/48'/0'/0'/2'  \r\n"
                     "3f635a63: " COS "\r\n";
  expect("CRLF, indented lines, path without m/", crlf, TWO_ACCOUNTS);
}

static void test_mixed(void) {
  const char *overrides = "Name: two-accounts\n"
                          "Policy: 2 of 3\n"
                          "Derivation: m/48'/0'/0'/2'\n"
                          "Format: P2WSH\n"
                          "\n"
                          "73C5DA0A: " OWN_0 "\n"
                          "Derivation: m/48'/0'/1'/2'\n"
                          "73C5DA0A: " OWN_1 "\n"
                          "Derivation: m/48'/0'/0'/2'\n"
                          "3F635A63: " COS "\n";
  expect("header path, then per-key overrides", overrides, TWO_ACCOUNTS);

  const char *comment = "# Derivation: m/48'/0'/1'/2' for the second key\n"
                        "Name: commented\n"
                        "Policy: 1 of 2\n"
                        "Derivation: m/48'/0'/0'/2'\n"
                        "Format: P2WSH\n"
                        "\n"
                        "73C5DA0A: " OWN_0 "\n"
                        "3F635A63: " COS "\n";
  expect("a derivation comment above the Derivation line is not applied",
         comment, "wsh(sortedmulti(1," O0 OWN_0 "," C0 COS "))");
}

/* BlueWallet writes "# derivation:" before a cosigner whose path differs from
 * the file's Derivation line, and only then: it applies to that key alone. */
static void test_bluewallet_key_derivation(void) {
  const char *custom = "# BlueWallet Multisig setup file\n"
                       "#\n"
                       "Name: bluewallet\n"
                       "Policy: 2 of 3\n"
                       "Derivation: m/48'/0'/0'/2'\n"
                       "Format: P2WSH\n"
                       "\n"
                       "73C5DA0A: " OWN_0_ZPUB "\n"
                       "# derivation: m/48'/0'/1'/2'\n"
                       "73C5DA0A: " OWN_1 "\n"
                       "3F635A63: " COS_ZPUB "\n";
  expect("'# derivation:' applies to the next key only", custom, TWO_ACCOUNTS);

  const char *no_global = "Name: bluewallet\n"
                          "Policy: 1 of 2\n"
                          "Format: P2WSH\n"
                          "\n"
                          "# derivation: m/48'/0'/0'/2'\n"
                          "73C5DA0A: " OWN_0 "\n"
                          "# derivation: m/48'/0'/1'/2'\n"
                          "73C5DA0A: " OWN_1 "\n";
  expect("every key with its own '# derivation:' and no Derivation line",
         no_global,
         "wsh(sortedmulti(1," O0 OWN_0 ",[73c5da0a/48'/0'/1'/2']" OWN_1 "))");
}

static void test_slip132(void) {
  const char *zpub = "# BlueWallet Multisig setup file\n"
                     "# this file contains only public keys and is safe to\n"
                     "# distribute among cosigners\n"
                     "#\n"
                     "Name: bluewallet\n"
                     "Policy: 2 of 2\n"
                     "Derivation: m/48'/0'/0'/2'\n"
                     "Format: P2WSH\n"
                     "\n"
                     "73C5DA0A: " OWN_0_ZPUB "\n"
                     "3F635A63: " COS_ZPUB "\n";
  expect("Zpub keys become xpub", zpub,
         "wsh(sortedmulti(2," O0 OWN_0 "," C0 COS "))");

  const char *ypub = "Name: wrapped\n"
                     "Policy: 2 of 2\n"
                     "Derivation: m/48'/0'/0'/1'\n"
                     "Format: P2SH-P2WSH\n"
                     "\n"
                     "73C5DA0A: " OWN_SH_YPUB "\n"
                     "3F635A63: " COS_SH_YPUB "\n";
  expect("Ypub keys become xpub", ypub,
         "sh(wsh(sortedmulti(2,[73c5da0a/48'/0'/0'/1']" OWN_SH
         ",[3f635a63/48'/0'/0'/1']" COS_SH ")))");

  const char *testnet = "Name: testnet\n"
                        "Policy: 1 of 2\n"
                        "Format: P2WSH-P2SH\n"
                        "\n"
                        "Derivation: m/48'/1'/0'/2'\n"
                        "73C5DA0A: " OWN_T2_VPUB "\n"
                        "Derivation: m/48'/1'/0'/1'\n"
                        "73C5DA0A: " OWN_T1_UPUB "\n";
  expect("vpub and upub keys become tpub", testnet,
         "sh(wsh(sortedmulti(1,[73c5da0a/48'/1'/0'/2']" OWN_T2
         ",[73c5da0a/48'/1'/0'/1']" OWN_T1 ")))");

  const char *multisig_versions = "Name: testnet\n"
                                  "Policy: 1 of 2\n"
                                  "Format: P2WSH-P2SH\n"
                                  "\n"
                                  "Derivation: m/48'/1'/0'/2'\n"
                                  "73C5DA0A: " OWN_T2_VPUB_MS "\n"
                                  "Derivation: m/48'/1'/0'/1'\n"
                                  "73C5DA0A: " OWN_T1_UPUB_MS "\n";
  expect("Vpub and Upub keys become tpub", multisig_versions,
         "sh(wsh(sortedmulti(1,[73c5da0a/48'/1'/0'/2']" OWN_T2
         ",[73c5da0a/48'/1'/0'/1']" OWN_T1 ")))");
}

#define HEAD "Name: bad\nPolicy: 1 of 2\nFormat: P2WSH\n"

static void test_malformed(void) {
  expect("NULL input", NULL, NULL);
  expect("plain descriptor is not a setup file",
         "wsh(sortedmulti(1," O0 OWN_0 "," C0 COS "))", NULL);
  expect("no Derivation line", HEAD "73c5da0a: " OWN_0 "\n3f635a63: " COS "\n",
         NULL);
  expect("key above every Derivation line",
         HEAD "73c5da0a: " OWN_0 "\nDerivation: m/48'/0'/0'/2'\n3f635a63: " COS
              "\n",
         NULL);
  expect("blank Derivation line",
         HEAD "Derivation: m/48'/0'/0'/2'\n73c5da0a: " OWN_0
              "\nDerivation:\n3f635a63: " COS "\n",
         NULL);
  expect("over-long Derivation path",
         HEAD "Derivation: m/48'/0'/0'/2'\n73c5da0a: " OWN_0
              "\nDerivation: m/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/"
              "20/21/22/23/24/25/26/27/28/29/30\n3f635a63: " COS "\n",
         NULL);
  expect("threshold above key count",
         "Policy: 3 of 2\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n"
         "73c5da0a: " OWN_0 "\n3f635a63: " COS "\n",
         NULL);
  expect("more than 15 keys",
         "Policy: 1 of 16\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n"
         "73c5da0a: " OWN_0 "\n",
         NULL);
  expect("fewer keys than the policy",
         HEAD "Derivation: m/48'/0'/0'/2'\n73c5da0a: " OWN_0 "\n", NULL);
  expect("unknown Format",
         "Policy: 1 of 2\nDerivation: m/48'/0'/0'/2'\nFormat: P2TR\n"
         "73c5da0a: " OWN_0 "\n3f635a63: " COS "\n",
         NULL);
  expect("bad xpub checksum",
         HEAD "Derivation: m/48'/0'/0'/2'\n73c5da0a: " OWN_0 "\n3f635a63: "
              "xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHq"
              "ytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybs\n",
         NULL);
}

int main(void) {
  printf("=== multisig_setup tests ===\n\n");

  test_single_header();
  test_per_key_derivation();
  test_mixed();
  test_bluewallet_key_derivation();
  test_slip132();
  test_malformed();

  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
