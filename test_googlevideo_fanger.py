#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from googlevideo_fanger import (
    Config,
    extract_googlevideo_hosts,
    is_googlevideo_host,
    normalize_host,
    parse_args,
    read_adguard_dns_query_log,
    read_env_file,
    render_blocklist,
    run_once,
)


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class GooglevideoFangerTests(unittest.TestCase):
    def test_normalize_and_validate(self):
        self.assertEqual(
            normalize_host("HTTPS://ABC.GOOGLEVIDEO.COM.:443/path"),
            "abc.googlevideo.com",
        )
        self.assertTrue(is_googlevideo_host("r1---sn-ab5l6n7e.googlevideo.com"))
        self.assertTrue(is_googlevideo_host("googlevideo.com"))
        self.assertFalse(is_googlevideo_host("notgooglevideo.com"))
        self.assertFalse(is_googlevideo_host("googlevideo.com.evil.example"))

    def test_exact_regex(self):
        text = (
            "r1---sn-ab5l6n7e.googlevideo.com\n"
            "A.B.GOOGLEVIDEO.COM\n"
            "xgooglevideo.com\n"
            "googlevideo.com.evil.example\n"
            "a.googlevideo.com."
        )
        self.assertEqual(
            extract_googlevideo_hosts(text),
            {"r1---sn-ab5l6n7e.googlevideo.com", "a.b.googlevideo.com"},
        )

    def test_alle_18_beispiele(self):
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
        self.assertEqual(len(extract_googlevideo_hosts(examples)), 18)

    def test_api_key_header_and_required_time_parameters(self):
        requests = []

        def opener(request, timeout):
            requests.append(request)
            return Response({"items": [{"domain": "r1.googlevideo.com"}], "pages": []})

        text = read_adguard_dns_query_log(
            "test-api-key", lookback_seconds=300, opener=opener
        )
        request = requests[0]
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
        self.assertEqual(request.get_header("Authorization"), "ApiKey test-api-key")
        self.assertIn("time_from_millis", params)
        self.assertIn("time_to_millis", params)
        self.assertEqual(params["search"], ["googlevideo.com"])
        self.assertEqual(params["limit"], ["1000"])
        self.assertEqual(text, "r1.googlevideo.com")

    def test_api_pagination(self):
        responses = iter(
            [
                Response(
                    {
                        "items": [{"domain": "r1.googlevideo.com"}],
                        "pages": [
                            {"current": True, "page_number": 1, "page_cursor": "p1"},
                            {"current": False, "page_number": 2, "page_cursor": "p2"},
                        ],
                    }
                ),
                Response(
                    {
                        "items": [{"domain": "r2.googlevideo.com"}],
                        "pages": [
                            {"current": False, "page_number": 1, "page_cursor": "p1"},
                            {"current": True, "page_number": 2, "page_cursor": "p2"},
                        ],
                    }
                ),
            ]
        )
        requests = []

        def opener(request, timeout):
            requests.append(request)
            return next(responses)

        text = read_adguard_dns_query_log("key", opener=opener)
        self.assertEqual(text, "r1.googlevideo.com\nr2.googlevideo.com")
        self.assertEqual(len(requests), 2)
        self.assertIn("cursor=p2", requests[1].full_url)

    def test_env_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.env"
            path.write_text(
                "# API-only\nADGUARD_DNS_API_KEY=test-key\nGV_INTERVAL=300\n",
                encoding="utf-8",
            )
            values = read_env_file(path)
            self.assertEqual(values["ADGUARD_DNS_API_KEY"], "test-key")
            self.assertEqual(values["GV_INTERVAL"], "300")

    def test_parse_args_laedt_api_key_aus_env_datei(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.env"
            path.write_text(
                "ADGUARD_DNS_API_KEY=file-api-key\nGV_INTERVAL=301\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                args, values = parse_args(["--env-file", str(path), "--once"])
            self.assertEqual(values["ADGUARD_DNS_API_KEY"], "file-api-key")
            self.assertEqual(args.interval, 301)

    def test_render_is_adguard_compatible(self):
        output = render_blocklist({"b.googlevideo.com", "a.googlevideo.com"})
        self.assertIn("||a.googlevideo.com^", output)
        self.assertIn("||b.googlevideo.com^", output)
        self.assertLess(output.index("a.googlevideo.com"), output.index("b.googlevideo.com"))

    def test_run_once_api_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "blocklist.txt"
            state = root / "state.json"
            allowlist = root / "allowlist.txt"
            allowlist.write_text("keep.googlevideo.com\n", encoding="utf-8")

            def opener(request, timeout):
                return Response(
                    {
                        "items": [
                            {"domain": "r1.googlevideo.com"},
                            {"domain": "keep.googlevideo.com"},
                            {"domain": "example.org"},
                        ],
                        "pages": [],
                    }
                )

            hosts = run_once(
                Config(
                    output=output,
                    state=state,
                    api_key="test-api-key",
                    allowlist=allowlist,
                ),
                opener=opener,
            )
            self.assertEqual(hosts, {"r1.googlevideo.com"})
            self.assertIn("||r1.googlevideo.com^", output.read_text(encoding="utf-8"))
            self.assertNotIn("keep.googlevideo.com", output.read_text(encoding="utf-8"))
            self.assertEqual(
                json.loads(state.read_text(encoding="utf-8"))["source"],
                "adguard-dns-query-log-api",
            )


if __name__ == "__main__":
    unittest.main()
