#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from googlevideo_fanger import (
    Config,
    extract_googlevideo_hosts,
    is_googlevideo_host,
    normalize_host,
    render_blocklist,
    run_once,
)


class GooglevideoFangerTests(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(normalize_host("HTTPS://ABC.GOOGLEVIDEO.COM.:443/path"), "abc.googlevideo.com")

    def test_only_googlevideo_suffix_is_accepted(self):
        self.assertTrue(is_googlevideo_host("r1---sn-ab5l6n7e.googlevideo.com"))
        self.assertTrue(is_googlevideo_host("googlevideo.com"))
        self.assertFalse(is_googlevideo_host("notgooglevideo.com"))
        self.assertFalse(is_googlevideo_host("googlevideo.com.evil.example"))

    def test_extracts_subdomains_and_deduplicates(self):
        text = "query r1---sn-ab5l6n7e.googlevideo.com\nquery R1---SN-AB5L6N7E.GOOGLEVIDEO.COM.\nquery example.com"
        self.assertEqual(extract_googlevideo_hosts(text), {"r1---sn-ab5l6n7e.googlevideo.com"})

    def test_render_is_adguard_compatible(self):
        output = render_blocklist({"b.googlevideo.com", "a.googlevideo.com"})
        self.assertIn("||a.googlevideo.com^", output)
        self.assertIn("||b.googlevideo.com^", output)
        self.assertLess(output.index("a.googlevideo.com"), output.index("b.googlevideo.com"))

    def test_run_once_writes_output_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "dns.log"
            output = root / "out" / "blocklist.txt"
            state = root / "state.json"
            allowlist = root / "allowlist.txt"
            source.write_text("r1.googlevideo.com\nkeep.googlevideo.com\nexample.org\n", encoding="utf-8")
            allowlist.write_text("keep.googlevideo.com\n", encoding="utf-8")
            hosts = run_once(Config(source, output, state, allowlist=allowlist))
            self.assertEqual(hosts, {"r1.googlevideo.com"})
            self.assertEqual(output.read_text(encoding="utf-8").count("||r1.googlevideo.com^"), 1)
            self.assertNotIn("keep.googlevideo.com", output.read_text(encoding="utf-8"))
            self.assertTrue(state.exists())


if __name__ == "__main__":
    unittest.main()
