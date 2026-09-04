#!/usr/bin/env python3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from googlevideo_fanger import (
    Config,
    extract_googlevideo_hosts,
    is_googlevideo_host,
    normalize_host,
    read_adguard_dns_query_log,
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

    def test_regex_gibt_den_vollstaendigen_query_treffer_zurueck(self):
        text = "query googlevideo.com\nquery a.b.googlevideo.com\nquery xgooglevideo.com\nquery googlevideo.com.evil.example"
        self.assertEqual(
            extract_googlevideo_hosts(text),
            {"googlevideo.com", "a.b.googlevideo.com"},
        )

    def test_wildcard_googlevideo_subdomains(self):
        text = "query one.googlevideo.com query two.three.googlevideo.com"
        self.assertEqual(
            extract_googlevideo_hosts(text),
            {"one.googlevideo.com", "two.three.googlevideo.com"},
        )

    def test_alle_18_beispiele_und_aehnliche_strukturen(self):
        examples = """rr4---sn-ci5gup-2o9l.googlevideo.com
r8.sn-w5nuxa-2tmz.googlevideo.com
r3---sn-hvcpaxvox-npos.googlevideo.com
rr7---sn-poqvn5u-ngbe.googlevideo.com
rr2---sn-p5qs7nzk.googlevideo.com
rr3---sn-bvvbaxivnuxqjvhj5nu-qxo6.googlevideo.com
rr7---sn-jvhj5nu-2iae.googlevideo.com
r6.sn-pjjoxu-q5je.googlevideo.com
rr3---sn-3c27sne7.googlevideo.com
rr2.sn-5ualdnz7.googlevideo.com
r5.sn-cvh7kn6z.googlevideo.com
rr2---sn-pmcg-4vgl.googlevideo.com
rr2.sn-f5f7lnl6.googlevideo.com
r1---sn-npoeen7y.googlevideo.com
r3.sn-5fo-0gue.googlevideo.com
rr3---sn-q4flrnl7.googlevideo.com
sn-cu-ajted.googlevideo.com
rr1.sn-gwpa-o5br.googlevideo.com"""
        hosts = extract_googlevideo_hosts(examples)
        self.assertEqual(len(hosts), 18)
        extra = "query A.B.GOOGLEVIDEO.COM query x-y.z-9.googlevideo.com:443/path"
        self.assertEqual(
            extract_googlevideo_hosts(extra),
            {"a.b.googlevideo.com", "x-y.z-9.googlevideo.com"},
        )

    def test_log_regex_lehnt_abschliessenden_punkt_ab(self):
        self.assertEqual(
            extract_googlevideo_hosts("query a.googlevideo.com."),
            set(),
        )

    def test_adguard_dns_api_liefert_nur_domainfelder(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"items":[{"domain":"r1.googlevideo.com"},{"domain":"example.org"}]}'

        with patch("googlevideo_fanger.urllib.request.urlopen", return_value=Response()) as opener:
            text = read_adguard_dns_query_log(
                "https://api.adguard-dns.io", "test-api-key"
            )
        request = opener.call_args.args[0]
        self.assertIn("/oapi/v1/query_log?", request.full_url)
        self.assertIn("search=googlevideo.com", request.full_url)
        self.assertEqual(request.get_header("Authorization"), "ApiKey test-api-key")
        self.assertEqual(text, "r1.googlevideo.com\nexample.org")

    def test_render_is_adguard_compatible(self):
        output = render_blocklist({"b.googlevideo.com", "a.googlevideo.com"})
        self.assertIn("||a.googlevideo.com^", output)
        self.assertIn("||b.googlevideo.com^", output)
        self.assertLess(output.index("a.googlevideo.com"), output.index("b.googlevideo.com"))

    def test_run_once_writes_output_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out" / "blocklist.txt"
            state = root / "state.json"
            allowlist = root / "allowlist.txt"
            allowlist.write_text("keep.googlevideo.com\n", encoding="utf-8")
            class Response:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def read(self):
                    return b'{"items":[{"domain":"r1.googlevideo.com"},{"domain":"keep.googlevideo.com"},{"domain":"example.org"}]}'

            with patch("googlevideo_fanger.urllib.request.urlopen", return_value=Response()):
                hosts = run_once(
                    Config(
                        output,
                        state,
                        allowlist=allowlist,
                        adguard_api_url="https://api.adguard-dns.io",
                        adguard_api_key="test-api-key",
                    )
                )
            self.assertEqual(hosts, {"r1.googlevideo.com"})
            self.assertEqual(output.read_text(encoding="utf-8").count("||r1.googlevideo.com^"), 1)
            self.assertNotIn("keep.googlevideo.com", output.read_text(encoding="utf-8"))
            self.assertTrue(state.exists())


if __name__ == "__main__":
    unittest.main()
