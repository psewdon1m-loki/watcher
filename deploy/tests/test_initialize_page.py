from __future__ import annotations

import struct
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INITIALIZE_ROOT = REPOSITORY_ROOT / "web" / "static" / "initialize"
PUBLIC_ORIGIN = "https://cakeproject.shmoza.net"


class HeadMetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta: dict[str, str] = {}
        self.links: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "meta":
            key = values.get("property") or values.get("name")
            content = values.get("content")
            if key and content:
                self.meta[key] = content
        elif tag == "link" and values.get("rel") and values.get("href"):
            self.links[values["rel"]] = values["href"]


class InitializePageMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (INITIALIZE_ROOT / "index.html").read_text(encoding="utf-8")
        cls.parser = HeadMetadataParser()
        cls.parser.feed(cls.html)

    def test_social_preview_uses_the_public_initialize_origin(self):
        expected_page = f"{PUBLIC_ORIGIN}/initialize/"
        image_urls = {
            self.parser.meta["og:image"],
            self.parser.meta["og:image:secure_url"],
            self.parser.meta["twitter:image"],
        }

        self.assertEqual(expected_page, self.parser.meta["og:url"])
        self.assertEqual(expected_page, self.parser.links["canonical"])
        self.assertEqual(1, len(image_urls))
        image_url = image_urls.pop()
        self.assertEqual("https", urlparse(image_url).scheme)
        self.assertEqual(urlparse(PUBLIC_ORIGIN).netloc, urlparse(image_url).netloc)
        self.assertNotIn("https://cake.shmoza.net", self.html)

    def test_social_preview_png_exists_and_matches_declared_dimensions(self):
        image_url = urlparse(self.parser.meta["og:image"])
        image_path = INITIALIZE_ROOT / Path(image_url.path).name
        with image_path.open("rb") as source:
            header = source.read(24)

        self.assertEqual(b"\x89PNG\r\n\x1a\n", header[:8])
        width, height = struct.unpack(">II", header[16:24])
        self.assertEqual(int(self.parser.meta["og:image:width"]), width)
        self.assertEqual(int(self.parser.meta["og:image:height"]), height)


if __name__ == "__main__":
    unittest.main()
