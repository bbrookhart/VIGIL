"""A deployment failure must never become evidence of network-policy enforcement."""

import pathlib
import subprocess
import unittest


class ProbeTests(unittest.TestCase):
    def probe(self, status, output):
        helper = pathlib.Path(__file__).with_name("http_probe.sh")
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; probe_http bash -c \'printf "%s" "$1"; exit "$2"\' -- "$2" "$3"',
             "probe-test", str(helper), output, str(status)],
            check=True, text=True, capture_output=True,
        )
        return result.stdout

    def test_expected_drop_is_single_zero_status(self):
        self.assertEqual(self.probe(28, "000"), "000")

    def test_dns_and_command_errors_are_not_policy_drops(self):
        for status in (1, 6, 7, 126, 127):
            with self.subTest(status=status):
                self.assertEqual(self.probe(status, "000"), f"transport-error-{status}")

    def test_timeout_without_curl_status_is_not_policy_evidence(self):
        self.assertEqual(self.probe(28, ""), "transport-error-28")

    def test_http_reachability_and_refusal_remain_visible(self):
        for code in ("200", "401", "403", "500"):
            self.assertEqual(self.probe(0, code), code)
