"""Synthetic JVN RSS bodies, each with the result ScanMux parseJvnRss gives.

``None`` means the body is refused. A window is summarized as
``(channel modified, oldest, newest, [(identifier, link, modified, cves), ...])``.
"""

from __future__ import annotations

from typing import Any

Window = tuple[str | None, str, str, list[tuple[str, str, str, list[str]]]]

HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<rdf:RDF\n  xmlns="http://purl.org/rss/1.0/"\n  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"\n'
    '  xmlns:dc="http://purl.org/dc/elements/1.1/"\n  xmlns:dcterms="http://purl.org/dc/terms/"\n  xml:lang="ja">\n'
)
CHANNEL = (
    ' <channel rdf:about="https://jvn.jp/rss/jvn.rdf">\n  <title>Example feed</title>\n  <link>https://jvn.jp/</link>\n'
    '  <dc:date>2026-10-26T17:46:49+09:00</dc:date>\n  <dcterms:modified>2026-10-26T17:46:49+09:00</dcterms:modified>\n'
    '  <items><rdf:Seq><rdf:li rdf:resource="https://jvn.jp/vu/JVNVU00000001/" /></rdf:Seq></items>\n </channel>\n'
)


def item(identifier: str = "JVNVU#00000001", link: str = "https://jvn.jp/vu/JVNVU00000001/",
         title: str = "Example product: CVE-2026-0001", description: str = "Synthetic advisory",
         modified: str = "2026-10-26T12:00+09:00", *, extra: str = "", time_field: str = "dcterms:modified") -> str:
    return (f' <item rdf:about="{link}">\n  <title>{title}</title>\n  <link>{link}</link>\n'
            f'  <description>{description}</description>\n  <dc:identifier>{identifier}</dc:identifier>\n'
            f'  <{time_field}>{modified}</{time_field}>\n{extra} </item>\n')


def rss(*items: str, channel: str = CHANNEL, head: str = HEAD, tail: str = "</rdf:RDF>\n") -> bytes:
    return (head + channel + "".join(items or (item(),)) + tail).encode("utf-8")


SECOND = item("JVN#00000002", "https://jvn.jp/jp/JVN00000002/", "Other product", "Fixes cve-2026-0002 and CVE-2026-0001",
              "2026-10-20T09:00:00Z")
ONE: Window = ("2026-10-26T17:46:49+09:00", "2026-10-26T12:00+09:00", "2026-10-26T12:00+09:00",
               [("JVNVU#00000001", "https://jvn.jp/vu/JVNVU00000001/", "2026-10-26T12:00+09:00", ["CVE-2026-0001"])])


def _cases() -> list[tuple[str, bytes, Window | None]]:
    cases: list[tuple[str, bytes, Window | None]] = [
        ("one item", rss(), ONE),
        ("two items, lowercase CVE, oldest and newest", rss(item(), SECOND), (
            "2026-10-26T17:46:49+09:00", "2026-10-20T09:00:00Z", "2026-10-26T12:00+09:00",
            [ONE[3][0], ("JVN#00000002", "https://jvn.jp/jp/JVN00000002/", "2026-10-20T09:00:00Z",
                         ["CVE-2026-0001", "CVE-2026-0002"])])),
        ("same instant keeps document order", rss(item(modified="2026-10-26T03:00:00Z"),
                                                  item("JVN#2", modified="2026-10-26T12:00+09:00")),
         ("2026-10-26T17:46:49+09:00", "2026-10-26T03:00:00Z", "2026-10-26T12:00+09:00",
          [("JVNVU#00000001", "https://jvn.jp/vu/JVNVU00000001/", "2026-10-26T03:00:00Z", ["CVE-2026-0001"]),
           ("JVN#2", "https://jvn.jp/vu/JVNVU00000001/", "2026-10-26T12:00+09:00", ["CVE-2026-0001"])])),
        ("sub-millisecond difference ties", rss(item(modified="2026-10-26T03:00:00.0009Z"),
                                                item("JVN#2", modified="2026-10-26T03:00:00.0001Z")),
         ("2026-10-26T17:46:49+09:00", "2026-10-26T03:00:00.0009Z", "2026-10-26T03:00:00.0001Z",
          [("JVNVU#00000001", "https://jvn.jp/vu/JVNVU00000001/", "2026-10-26T03:00:00.0009Z", ["CVE-2026-0001"]),
           ("JVN#2", "https://jvn.jp/vu/JVNVU00000001/", "2026-10-26T03:00:00.0001Z", ["CVE-2026-0001"])])),
        ("no channel time", rss(channel=" <channel><title>t</title></channel>\n"), (None, *ONE[1:])),
        ("no channel", rss(channel=""), (None, *ONE[1:])),
        ("broken channel time is null", rss(channel=" <channel><dcterms:modified>soon</dcterms:modified></channel>\n"),
         (None, *ONE[1:])),
        ("dc:date when dcterms:modified is absent", rss(item(time_field="dc:date")), ONE),
        ("CVE as a whole token only", rss(item(title="CVE-2026-0001x xCVE-2026-0002 CVE-2026-0003_ -CVE-2026-0004 "
                                                     "CVE-2026-00005 (CVE-2026-0006)")),
         ("2026-10-26T17:46:49+09:00", ONE[1], ONE[2],
          [(ONE[3][0][0], ONE[3][0][1], ONE[3][0][2], ["CVE-2026-00005", "CVE-2026-0006"])])),
        ("CVE in description, entity and CDATA", rss(item(title="T &amp; CVE&#x2D;2026-0007",
                                                          description="<![CDATA[CVE-2026-0008 <b>]]>")),
         ("2026-10-26T17:46:49+09:00", ONE[1], ONE[2],
          [(ONE[3][0][0], ONE[3][0][1], ONE[3][0][2], ["CVE-2026-0007", "CVE-2026-0008"])])),
        ("CVE across a line break is not a token", rss(item(title="CVE-2026-\n0009")),
         ("2026-10-26T17:46:49+09:00", ONE[1], ONE[2], [(*ONE[3][0][:3], [])])),
        ("very long CVE number is dropped", rss(item(title="CVE-2026-" + "1" * 60)),
         ("2026-10-26T17:46:49+09:00", ONE[1], ONE[2], [(*ONE[3][0][:3], [])])),
        ("fields are trimmed with JS whitespace", rss(item(identifier="　JVNVU#00000001﻿ ")), ONE),
        ("unknown fields may hold markup", rss(item(extra="  <dc:creator><x>y</x></dc:creator>\n")), ONE),
        ("comment is skipped", rss(item(extra="  <!-- <item>x</item> -->\n")), ONE),
        ("comment before the root", rss(head='<?xml version="1.0"?>\n<!-- c -->\n<rdf:RDF>'), ONE),
        ("no declaration", rss(head="<rdf:RDF>\n"), ONE),
        ("one BOM is removed", b"\xef\xbb\xbf" + rss(), ONE),
        ("two BOMs with a declaration", b"\xef\xbb\xbf\xef\xbb\xbf" + rss(), ONE),
        ("three BOMs without a declaration", b"\xef\xbb\xbf" * 3 + rss(head="<rdf:RDF>\n"), ONE),
        ("empty elements and attributes", rss(item(extra='  <x a="1" b=\'2\'/>\n')), ONE),
        ("seconds-less offset time", rss(item(modified="2026-10-26T12:00-01:30")),
         ("2026-10-26T17:46:49+09:00", "2026-10-26T12:00-01:30", "2026-10-26T12:00-01:30",
          [(*ONE[3][0][:2], "2026-10-26T12:00-01:30", ["CVE-2026-0001"])])),
        ("year 0000", rss(item(modified="0000-02-29T00:00Z")),
         ("2026-10-26T17:46:49+09:00", "0000-02-29T00:00Z", "0000-02-29T00:00Z",
          [(*ONE[3][0][:2], "0000-02-29T00:00Z", ["CVE-2026-0001"])])),
    ]
    refused: list[tuple[str, bytes]] = [
        ("DOCTYPE", rss(head='<?xml version="1.0"?>\n<!DOCTYPE rdf:RDF [<!ENTITY x "y">]>\n<rdf:RDF>')),
        ("unknown entity", rss(item(title="&x;"))),
        ("bare ampersand", rss(item(title="a & b"))),
        ("entity in attribute", rss(item(extra='  <x a="&nope;"/>\n'))),
        ("duplicate attribute", rss(item(extra='  <x a="1" a="2"/>\n'))),
        ("character reference to NUL", rss(item(title="&#0;"))),
        ("character reference to a surrogate", rss(item(title="&#xD800;"))),
        ("character reference beyond Unicode", rss(item(title="&#x110000;"))),
        ("control character", rss(item(title="a\x01b"))),
        ("invalid UTF-8", rss()[:-3] + b"\xff>\n"),
        ("processing instruction", rss(item(extra="  <?pi x?>\n"))),
        ("three BOMs before a declaration", b"\xef\xbb\xbf" * 3 + rss()),
        ("second declaration", rss(head='<?xml version="1.0"?><?xml version="1.0"?>\n<rdf:RDF>')),
        ("double hyphen in comment", rss(item(extra="  <!-- a -- b -->\n"))),
        ("comment ending in hyphen", rss(item(extra="  <!-- a --->\n"))),
        ("unclosed comment", rss(tail="</rdf:RDF><!-- ")),
        ("CDATA outside the root", rss(tail="</rdf:RDF><![CDATA[x]]>")),
        ("unclosed CDATA", rss(item(title="<![CDATA[x"))),
        ("mismatched end tag", rss(item(extra="  <x></y>\n"))),
        ("unclosed root", rss(tail="")),
        ("text after the root", rss(tail="</rdf:RDF>\ntext")),
        ("second root", rss(tail="</rdf:RDF><rdf:RDF></rdf:RDF>")),
        ("wrong root", rss(head="<rss>", tail="</rss>")),
        ("item inside channel", rss(channel=" <channel>" + item() + "</channel>\n")),
        ("no items", rss(item(), channel=CHANNEL).replace(item().encode(), b"")),
        ("duplicate field", rss(item(extra="  <title>again</title>\n"))),
        ("known field with a child", rss(item(description="a <b>bold</b> b"))),
        ("channel field with a child", rss(channel=" <channel><dc:date><x/></dc:date></channel>\n")),
        ("missing identifier", rss(item().replace("<dc:identifier>JVNVU#00000001</dc:identifier>", "<x/>"))),
        ("identifier shape", rss(item(identifier="JVNvu#1"))),
        ("identifier too long", rss(item(identifier="JVN#" + "1" * 33))),
        ("missing title", rss(item().replace("<title>Example product: CVE-2026-0001</title>", ""))),
        ("link host", rss(item(link="https://jvn.jp.example/x"))),
        ("link with a space", rss(item(link="https://jvn.jp/a b"))),
        ("link over 500 characters", rss(item(link="https://jvn.jp/" + "a" * 501))),
        ("bad item time", rss(item(modified="2026-02-30T00:00Z"))),
        ("hour 24", rss(item(modified="2026-10-26T24:00Z"))),
        ("no offset", rss(item(modified="2026-10-26T12:00:00"))),
        ("broken dcterms:modified does not fall back",
         rss(item(extra="  <dc:date>2026-10-26T12:00Z</dc:date>\n", modified="never"))),
        ("empty dcterms:modified does not fall back",
         rss(item(extra="  <dc:date>2026-10-26T12:00Z</dc:date>\n", modified=""))),
        ("too many items", rss(*(item(f"JVN#{n}") for n in range(1001)))),
        ("tag name with a non-ASCII letter", rss(item(extra="  <é/>\n"))),
        ("NEL is not JS whitespace outside the root", rss(tail="</rdf:RDF>\u0085")),
    ]
    return cases + [(name, body, None) for name, body in refused]


CASES = _cases()


def window_summary(window: Any) -> Window:
    """The comparable form of a parsed window from patchwait."""
    return (window.modified, window.oldest, window.newest,
            [(item.identifier, item.link, item.modified, list(item.cves)) for item in window.items])
