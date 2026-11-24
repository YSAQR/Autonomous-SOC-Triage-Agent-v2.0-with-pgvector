"""Unit tests for deterministic log pre-filtering and time-window batching."""

from __future__ import annotations

from pathlib import Path
import unittest

from app.engine.parser import parse_and_batch_logs

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_logs"


class TestLogParser(unittest.TestCase):
    """Verify compiled regex parsing, benign discarding, and indicator extraction."""

    def test_sample_auth_log_parsing(self) -> None:
        raw_text = (SAMPLE_DIR / "auth.log").read_text(encoding="utf-8")
        result = parse_and_batch_logs(raw_text, source_hint="auth.log", reference_year=2026)

        self.assertEqual(result.detected_source, "auth.log")
        self.assertGreater(result.benign_discarded, 0)
        self.assertGreaterEqual(result.suspicious_total, 12)
        self.assertEqual(len(result.batches), 1)

        batch = result.batches[0]
        self.assertIn("185.220.101.45", batch.extracted_ips)
        self.assertIn("45.155.205.233", batch.extracted_ips)
        self.assertIn("root", batch.extracted_usernames)
        self.assertIn("deploy", batch.extracted_usernames)
        self.assertIn("sudo_unauthorized_attempt", batch.category_counts)
        self.assertIn("ssh_root_login_accepted", batch.category_counts)

    def test_sample_access_log_parsing(self) -> None:
        raw_text = (SAMPLE_DIR / "access.log").read_text(encoding="utf-8")
        result = parse_and_batch_logs(raw_text, source_hint="access.log")

        self.assertEqual(result.detected_source, "access.log")
        self.assertEqual(result.benign_discarded, 4)
        self.assertEqual(result.suspicious_total, 9)
        self.assertEqual(len(result.batches), 1)

        batch = result.batches[0]
        self.assertIn("91.240.118.172", batch.extracted_ips)
        self.assertIn("194.26.135.88", batch.extracted_ips)
        self.assertNotIn("10.0.1.15", batch.extracted_ips)
        self.assertIn("web_exploit_payload", batch.category_counts)
        self.assertIn("http_401_error_spike", batch.category_counts)

    def test_benign_only_logs_produce_zero_batches(self) -> None:
        benign = (
            '10.0.0.5 - - [24/Nov/2026:12:00:01 +0000] "GET /static/app.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            'Nov 24 12:00:02 host systemd[1]: Started Daily apt activities.\n'
        )
        result = parse_and_batch_logs(benign, source_hint="auto")
        self.assertEqual(result.suspicious_total, 0)
        self.assertEqual(result.benign_discarded, 2)
        self.assertEqual(result.batches, [])


if __name__ == "__main__":
    unittest.main()
