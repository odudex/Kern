#!/usr/bin/env python3
"""Regression checks for sensitive camera entropy UI handling."""

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
CAMERA_PAGE = REPO_ROOT / "main/pages/new_mnemonic/entropy_from_camera.c"
STORAGE_BROWSER = REPO_ROOT / "main/pages/shared/storage_browser.c"
SIMULATOR_CMAKE = REPO_ROOT / "simulator/CMakeLists.txt"


class CameraEntropyConfirmationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CAMERA_PAGE.read_text(encoding="utf-8")

    def test_confirmation_does_not_hex_encode_entropy(self):
        self.assertNotIn("%02x", self.source)
        self.assertNotIn("hex_hash", self.source)
        self.assertNotIn("Snapshot + TRNG digest", self.source)
        self.assertNotIn("digest", self.source.lower())
        self.assertNotIn("checksum", self.source.lower())
        self.assertNotIn("raw bytes", self.source.lower())

    def test_confirmation_uses_non_secret_copy_and_explicit_controls(self):
        self.assertIn(
            '"Image diversity check passed.\\n"', self.source
        )
        self.assertIn('"Camera input combined with device randomness."', self.source)
        self.assertIn('theme_create_button(entropy_screen, "Retake", false)', self.source)
        self.assertIn('theme_create_button(entropy_screen, "Proceed", true)', self.source)

    def test_retake_relaunches_capture_with_preserved_word_count(self):
        retake_cb = re.search(
            r"static void capture_confirmation_retake_cb\(lv_event_t \*e\) \{(.*?)\n\}",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(retake_cb)
        if retake_cb is None:
            return
        body = retake_cb.group(1)
        self.assertIn("secure_memzero(entropy_hash, sizeof(entropy_hash));", body)
        self.assertIn("hash_captured = false;", body)
        self.assertIn("on_word_count_selected(total_words);", body)
        self.assertNotIn("create_word_count_menu", body)

    def test_entropy_is_not_passed_to_display_or_logging_calls(self):
        sensitive_sink = re.compile(
            r"(?:lv_label_set_text|snprintf|printf|ESP_LOG[A-Z]*)\s*\([^;]*entropy_hash",
            re.DOTALL,
        )
        self.assertIsNone(sensitive_sink.search(self.source))


class StorageBrowserIntegrationTests(unittest.TestCase):
    def test_both_listing_paths_use_distinct_status_message_helper(self):
        source = STORAGE_BROWSER.read_text(encoding="utf-8")
        self.assertEqual(source.count("storage_browser_list_message("), 1)
        self.assertEqual(source.count("if (handle_list_status("), 2)
        self.assertNotIn("ret != ESP_OK || raw_count == 0", source)

    def test_internal_errors_are_not_classified_as_sd_access_failures(self):
        source = STORAGE_BROWSER.read_text(encoding="utf-8")
        self.assertIn("ret == ESP_ERR_NO_MEM || ret == ESP_ERR_INVALID_ARG", source)
        self.assertIn("STORAGE_BROWSER_LIST_INTERNAL_ERROR", source)
        self.assertIn("STORAGE_BROWSER_LIST_SD_UNAVAILABLE", source)

    def test_simulator_links_storage_browser_message_helper(self):
        source = SIMULATOR_CMAKE.read_text(encoding="utf-8")
        self.assertIn(
            "${APP_PAGES_DIR}/shared/storage_browser_messages.c", source
        )


if __name__ == "__main__":
    unittest.main()
