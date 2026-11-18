"""The offline wiki: one file that opens without a network.

The VM has no internet access, so whoever works there cannot open GitHub or a
documentation site: `make docs` turns docs/ into webui/static/wiki.html, and
that file has to carry everything it needs. The promises held here are the ones
that break silently - a stylesheet over https that never loads on the VM, an
<img> with a relative path that shows a broken frame, an ES module that a
browser refuses from file://, a dead diagram because the pinned Mermaid copy
changed, and markdown that becomes live HTML.

One test builds the real wiki (the fifteen pages and the 30 screenshots, about
16 MB); everything else builds a small fixture wiki in tmp_path, so the suite
does not pay for 12 MB of Base64 per assertion.
"""

import calendar
import datetime
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
STATIC = os.path.join(ROOT, "static")
MERMAID = os.path.join(ROOT, "scripts", "wiki", "mermaid.min.js")


def _load_generator():
    """scripts/build-wiki.py is a script, not a package: load it by path."""
    path = os.path.join(ROOT, "scripts", "build-wiki.py")
    spec = importlib.util.spec_from_file_location("tdc_build_wiki", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wiki = _load_generator()


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _no_mermaid(html):
    """The document without the pinned Mermaid bundle.

    The bundle is third-party minified code: it carries the SVG namespace URL,
    d3's fetch wrapper and other strings that a search for "http" or "fetch("
    would hit. It is pinned by version and SHA-256 instead
    (test_the_build_refuses_a_missing_or_changed_mermaid), so the scans for
    network use run over our own HTML, CSS and JavaScript.
    """
    start = html.index(wiki.MERMAID_SCRIPT_OPEN)
    end = html.index("</script>", start)
    return html[:start] + html[end + len("</script>"):]


def _index_data(html):
    """The search index the document carries, as Python data.

    The literal writes every "<" as \\u003c (so a line of the guide can never
    close the script that carries it), which json.loads reads back as itself.
    """
    m = re.search(r"const WIKI_INDEX = (\[.*?\]);\n", html, re.S)
    assert m, "the document carries no WIKI_INDEX"
    return json.loads(m.group(1))


def _ids(html):
    return set(re.findall(r'<(?:h[1-6]|section)[^>]*\bid="([^"]+)"', html))


@pytest.fixture(scope="module")
def real_wiki(tmp_path_factory):
    """The wiki of this repository, built once for the whole module."""
    out = tmp_path_factory.mktemp("wiki") / "wiki.html"
    html = wiki.build_wiki(DOCS, STATIC, MERMAID, str(out))
    assert os.path.getsize(str(out)) > 1_000_000, "a wiki without its images"
    return html


def _fixture_docs(tmp_path, pages):
    """A small docs/ tree: the index links every page, in the given order."""
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    index = ["# Fixture index", "", "An index for the tests.", ""]
    for name in pages:
        index.append("- [%s](%s)" % (name, name))
    (docs / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    for name, body in pages.items():
        (docs / name).write_text(body, encoding="utf-8")
    return docs


def _build(tmp_path, pages, images=()):
    """Build a fixture wiki and return its HTML."""
    docs = _fixture_docs(tmp_path, pages)
    static = tmp_path / "static"
    static.mkdir(exist_ok=True)
    for name in images:
        # the smallest valid PNG: 1x1, fully transparent
        (static / name).write_bytes(bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
            "890000000a49444154789c6300010000050001"
            "0d0a2db40000000049454e44ae426082"))
    out = tmp_path / "wiki.html"
    return wiki.build_wiki(str(docs), str(static), MERMAID, str(out))


# --- The file itself ---------------------------------------------------------


def _own_chrome(html):
    """The document without the Mermaid bundle, the guide's text and the index.

    What is left is what the generator writes itself: the style sheet, the
    navigation, the footer and the wiki's own JavaScript. The pages and the
    search index must be cut out for this scan, because the guide legitimately
    writes about `fetch`, about the page's `sendBeacon` on pagehide and about
    `http://localhost:9000` - prose and code text, not resources. The index is
    data: a JSON array of strings, which the search puts into the page with
    textContent (and which carries no raw "<", see
    test_the_search_index_cannot_break_its_own_script).
    """
    body = _no_mermaid(html)
    start = body.index('<main class="content">')
    end = body.index("</main>") + len("</main>")
    body = body[:start] + body[end:]
    index = re.search(r"const WIKI_INDEX = (\[.*?\]);\n", body, re.S)
    assert index, "the document carries no WIKI_INDEX"
    assert re.match(r'^\[(?:\{"p":".*?"\},?)*\]$', index.group(1)), \
        "the index literal is not a plain array of records"
    return body[:index.start(1)] + body[index.end(1):]


# Every way a document can ask the network for something, in the shapes they
# take in HTML, CSS and JavaScript. Six mutations of the generator used to pass
# the whole file: an @font-face and a background over http, new Image().src,
# navigator.sendBeacon, a dynamic import() and an EventSource.
RESOURCE_SHAPES = [
    (r"@import", "a style sheet import"),
    (r"url\(", "a CSS url()"),
    (r"\bfetch\s*\(", "a fetch call"),
    (r"XMLHttpRequest", "an XMLHttpRequest"),
    (r"\bEventSource\b", "an EventSource"),
    (r"sendBeacon", "a beacon"),
    (r"\bimport\s*\(", "a dynamic import"),
    (r"new\s+Image\b", "an Image loader"),
    (r"new\s+WebSocket\b", "a WebSocket"),
    (r"\.src\s*=", "an assignment to .src"),
    (r"serviceWorker", "a service worker"),
    (r"<link\b", "a linked resource"),
    (r"<(?:iframe|object|embed|audio|video)\b", "an embedded resource"),
    (r'type="module"', "an ES module, which file:// refuses"),
]


def test_the_wiki_is_one_file_that_needs_no_network(real_wiki):
    html = _no_mermaid(real_wiki)
    chrome = _own_chrome(real_wiki)
    # 1. Nothing the generator writes itself may reach for the network, in any
    # of its shapes - not only over https.
    for pattern, what in RESOURCE_SHAPES:
        m = re.search(pattern, chrome)
        assert m is None, "the wiki carries %s: %r" % (
            what, chrome[max(0, m.start() - 70):m.start() + 70])
    assert "http://" not in chrome and "https://" not in chrome, \
        "a URL in the wiki's own style sheet, navigation, footer or script"
    # 2. An http(s) URL may only stand in an href - a link in the prose is
    # followed on a host that has a network, it is not loaded with the page.
    for attr, value in re.findall(r'\s([a-zA-Z-]+)="([^"]*)"', html):
        if "http://" in value or "https://" in value:
            assert attr == "href", "%s=%r loads over the network" % (attr, value[:80])
    # 3. Every picture is in the file
    for attr in re.findall(r'\b(?:src|srcset|poster|data)="([^"]*)"', html):
        assert attr.startswith("data:"), "a src over the network: %s" % attr[:80]
    srcs = re.findall(r'<img[^>]*\bsrc="([^"]*)"', html)
    assert len(srcs) >= 29, "the screenshots of the guide are missing: %d" % len(srcs)
    for src in srcs:
        assert src.startswith("data:image/png;base64,"), src[:60]
    # 4. The pinned Mermaid copy is in the document, not loaded from a CDN
    assert wiki.MERMAID_VERSION in real_wiki
    bundle = open(MERMAID, encoding="utf-8").read()
    assert bundle[:200] in real_wiki, "the pinned Mermaid bundle is not embedded"
    assert "cdn.jsdelivr.net" not in html and "unpkg.com" not in html
    # 5. demo.gif (10 MB) is named and linked into the repository, never embedded
    # and never relative: no deploy path carries static/ to the VM.
    assert "demo.gif" in html, "the wiki does not mention the demo video"
    assert "data:image/gif" not in html
    assert 'src="static/demo.gif"' not in html and "../static/demo.gif" not in html
    note = html[html.index("demo.gif") - 400:html.index("demo.gif") + 400]
    assert wiki.REPO_URL in note, "the demo video is not linked into the repository"
    assert "network" in note.lower(), "nothing says that the video needs a network"


def test_the_navigation_follows_the_index(real_wiki):
    order = wiki.page_order(_read("docs", "README.md"))
    # The index and fourteen pages, the set the design fixes (FIREWALL added one). A pin, not a
    # floor - but one that says what to do (round 4, Minor 2): a page added to
    # the guide is a change of that design, so this number moves with it.
    assert order[0] == "README.md" and len(order) == 15, \
        "the guide is the index and fourteen pages; it has %d. If docs/ gained " \
        "or lost a page on purpose, update this number: %s" % (len(order), order)
    nav = real_wiki[real_wiki.index('<nav id="toc"'):real_wiki.index("</nav>")]
    pages = re.findall(r'<a class="toc-page" href="#([^"]+)"', nav)
    assert pages == [wiki.page_id(name) for name in order], pages
    ids = _ids(real_wiki)
    # Every page keeps its own ## headings under it, each with a jump target
    for name in order:
        body = _read("docs", name)
        want = [wiki.heading_id(name, t) for t in re.findall(r"^## (.+)$", body, re.M)]
        start = nav.index('href="#%s"' % wiki.page_id(name))
        end = nav.find('<a class="toc-page"', start)
        section = nav[start:end if end != -1 else len(nav)]
        got = re.findall(r'<a class="toc-head" href="#([^"]+)"', section)
        assert got == want, "the navigation of docs/%s: %s" % (name, got)
    for target in re.findall(r'<a class="toc-(?:page|head)" href="#([^"]+)"', nav):
        assert target in ids, "the navigation jumps to #%s, which is nowhere" % target
    # The id scheme itself, not only its own output: a page is its file stem, a
    # heading is "page--slug" the way GitHub slugs it, so the anchors the docs
    # already write (`](#charts)`) keep working inside the wiki.
    assert '<a class="toc-page" href="#rizin"' in nav
    assert '<a class="toc-head" href="#rizin--sessions"' in nav
    assert '<a class="toc-head" href="#web-ui--charts"' in nav
    assert '<a class="toc-page" href="#readme"' in nav, "the index page is #readme"


def test_the_search_finds_a_word_from_a_deep_page(real_wiki):
    records = _index_data(real_wiki)
    assert len(records) > 500, "the search index is too thin: %d lines" % len(records)
    # DECOMPILER is the name of a view of the RIZIN tab and stands in no other
    # page of the guide, so a hit for it has to carry rizin.md
    hits = [r for r in records if "DECOMPILER" in r["t"]]
    assert hits, "the search index does not know DECOMPILER"
    assert {r["p"] for r in hits} == {"rizin"}, {r["p"] for r in hits}
    for hit in hits:
        assert hit["pt"] == "Rizin", hit
        assert hit["h"] in _ids(real_wiki), hit
        assert hit["ht"], "a hit without its heading: %s" % hit
    # Round 4, Important 2: every hit, not only the ones this test looks up by
    # name. A `##` comment inside a YAML or PowerShell block was read as a
    # heading, so a record could carry an anchor that is nowhere in the
    # document - a hit that jumps nowhere - and its label named a command
    # instead of a section.
    ids = _ids(real_wiki)
    headings = {text for _, _, text in wiki.headings(real_wiki)}
    titles = {r["pt"] for r in records}
    for record in records:
        assert record["h"] in ids, "a search hit jumps nowhere: %s" % record
        assert record["ht"] in headings or record["ht"] in titles, \
            "a hit is filed under %r, which is no heading of the guide: %s" % (
                record["ht"], record)
    # The search runs in the browser: the index is data in the document, and
    # nothing asks a server for it
    assert "WIKI_INDEX" in real_wiki


def test_the_search_finds_the_lines_inside_a_code_block(real_wiki):
    """Round 4, Important 2: a `#` comment inside a fence was taken for a
    heading, which skipped the line - so `Enable Hyper-V`, `reboot required`,
    `Find VM IP` and `ipconfig`, each a comment line of a command block of
    docs/setup.md and docs/troubleshooting.md, stood on the page and were
    findable nowhere. Only a mermaid fence is skipped: a diagram's node labels
    are not prose."""
    records = _index_data(real_wiki)
    for term in ("Enable Hyper-V", "reboot required", "Find VM IP", "ipconfig"):
        hits = [r for r in records if term.lower() in r["t"].lower()]
        assert hits, "the search index does not know %r, which is on a page" % term
    # and no record is the inside of a diagram
    for name in wiki.page_order(_read("docs", "README.md")):
        for body in re.findall(r"^```mermaid[ \t]*\n(.*?)^```[ \t]*$",
                               _read("docs", name), re.M | re.S):
            for line in body.splitlines():
                node = re.search(r'\["([^"]{12,})"\]', line)
                if node:
                    assert not [r for r in records if r["t"] == node.group(1)], \
                        "a diagram's node label is in the search index: %r" % node.group(1)


def test_the_diagrams_are_rendered_by_the_embedded_mermaid(real_wiki):
    """Every mermaid block of a page of the guide is a <pre class="mermaid"> in
    the wiki, in the pages' order and with its type - the count comes from the
    pages themselves, so a fifth diagram (the design sanctions four to six) is
    carried instead of failing here (round 4, Minor 2)."""
    want = []
    for name in wiki.page_order(_read("docs", "README.md")):
        for body in re.findall(r"^```mermaid[ \t]*\n(.*?)^```[ \t]*$",
                               _read("docs", name), re.M | re.S):
            want.append(body.strip().split("\n")[0].strip())
    assert 4 <= len(want) <= 6, \
        "the design wants four to six diagrams in the guide, it has %d" % len(want)
    blocks = re.findall(r'<pre class="mermaid">(.*?)</pre>', real_wiki, re.S)
    kinds = [b.strip().split("\n")[0].strip() for b in blocks]
    assert kinds == want, \
        "the wiki draws %s, the guide has %s" % (kinds, want)
    for block in blocks:
        assert "<" not in block.replace("&lt;", ""), "a diagram carries live HTML"
    assert "mermaid.initialize" in real_wiki


# --- The parser --------------------------------------------------------------


NETWORK_NOTE = "needs network access, which the VM does not have"


def test_a_link_into_the_repository_says_it_needs_a_network(real_wiki):
    """Round 4, Important 3: the generator rewrites a `../`-link of the guide
    into a blob/main URL on github.com - the repository README, Vagrantfile.utm
    - and only the demo-video note said that a link like that needs a network.
    On the VM every one of them is a dead end, and nothing on the page said so.
    Each rewritten link carries the same note now."""
    rewritten = list(re.finditer(
        r'<a href="%s[^"]*"[^>]*>.*?</a>' % re.escape(wiki.REPO_BLOB), real_wiki, re.S))
    assert len(rewritten) >= 3, \
        "the guide's links into the repository are not being rewritten: %d" % len(rewritten)
    for m in rewritten:
        after = real_wiki[m.end():m.end() + 160]
        assert NETWORK_NOTE in after, \
            "a link into the repository without the note: %r" % real_wiki[
                m.start():m.end() + 80]
    # The note is written once per link, not once per page
    assert real_wiki.count(NETWORK_NOTE) >= len(rewritten), real_wiki.count(NETWORK_NOTE)


def test_a_link_out_of_docs_is_noted_but_an_inside_link_is_not(tmp_path):
    """The note belongs to a link the reader cannot follow on the VM. A link to
    another page of the guide, an anchor and a plain web link in the prose are
    not rewritten into the repository, so they get none."""
    page = """# P

What it answers.

The showcase is the [README](../README.md), its tab table is
[there](../README.md#web-ui-tabs), the guide's own [index](README.md) is here,
and [rizin](https://rizin.re) is a project.

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    body = html[html.index('data-page="page"'):]
    body = body[:body.index("</section>")]
    assert body.count(NETWORK_NOTE) == 2, body
    for link in re.findall(r'<a href="([^"]+)"[^>]*>', body):
        follows = body[body.index('href="%s"' % link):]
        follows = follows[:follows.index("</a>") + 120]
        if link.startswith(wiki.REPO_BLOB):
            assert NETWORK_NOTE in follows, link
        else:
            assert NETWORK_NOTE not in follows, "%s is not a link into the repository" % link


def test_page_order_reads_the_index():
    order = wiki.page_order(_read("docs", "README.md"))
    assert order == ["README.md", "setup.md", "installation.md", "configuration.md",
                     "workflow.md", "memory.md", "pipes.md", "rizin.md", "logs.md",
                     "firewall.md", "updates.md", "web-ui.md", "api.md", "development.md",
                     "troubleshooting.md"], order
    # A link that is not a page of the guide is not a page of the wiki
    assert wiki.page_order("# x\n[up](../README.md) [web](https://example.com)\n") \
        == ["README.md"]


def test_markdown_is_rendered_and_nothing_is_swallowed(tmp_path):
    page = """# The page

What it answers.

## A list

- one
  - nested one
  - nested two
- two

1. first
2. second

## A table

| Flag | What it does |
|---|---|
| `a\\|b` | A pipe in the text |
| **bold** | A cell with `code` |

## A code block

```python
print("hi")
# three backticks inside: ``` stays
```

## `Backticks` in a heading

> A blockquote, with *italics*.

---

![A picture](../static/shot.png)

A [link](https://example.com/x) and **bold** and *italics* and `inline`.

:::note this line is not markdown I know:::

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page}, images=["shot.png"])
    assert "<ul>" in html and html.count("<ul>") >= 2, "the nested list is flat"
    assert "<li>nested one</li>" in html
    assert "<ol>" in html and "<li>first</li>" in html
    assert "<table>" in html and "<th>Flag</th>" in html
    assert "a|b" in html, "the escaped pipe did not survive the table"
    assert "<strong>bold</strong>" in html and "<code>code</code>" in html
    assert '<pre class="code"><code class="language-python">' in html
    assert 'print(&quot;hi&quot;)' in html
    assert "three backticks inside: ``` stays" in html, "the fence ate its content"
    assert "<blockquote>" in html and "<em>italics</em>" in html
    assert "<hr" in html
    assert '<img src="data:image/png;base64,' in html and 'alt="A picture"' in html
    assert '<a href="https://example.com/x" target="_blank" rel="noopener">link</a>' in html
    assert "<code>inline</code>" in html
    # A heading with backticks keeps its code span and still has a plain id
    assert "<code>Backticks</code> in a heading" in html
    assert 'id="page--backticks-in-a-heading"' in html
    # What the parser does not know stays readable instead of disappearing
    assert ":::note this line is not markdown I know:::" in html


def test_markdown_cannot_inject_html(tmp_path):
    page = """# Danger

What it answers.

<script>alert(1)</script>

<img src=x onerror="alert(2)">

A span of <b>bold</b> HTML and a [link](javascript:alert(3)).

A picture as a link target: [svg](data:image/svg+xml,%3Csvg%20onload=alert(6)%3E).

```html
<script>alert(4)</script>
```

| Cell | <script>alert(5)</script> |
|---|---|
| a | b |

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    body = html[html.index('data-page="page"'):]
    body = body[:body.index("</section>")]
    assert "<script>" not in body and "</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert re.search(r"<[a-zA-Z][^>]*onerror", body) is None, \
        "an event handler became live HTML"
    assert "&lt;img src=x onerror=" in body
    assert "<b>bold</b>" not in body and "&lt;b&gt;bold&lt;/b&gt;" in body
    assert "javascript:" not in body.replace("javascript:alert(3)", "")
    assert "alert(3)" in body, "the refused link lost its text"
    # data: is what an embedded picture needs in a src, not what a link needs
    # in an href (round 1, Minor 10)
    assert 'href="data:' not in body, "a data: URI as a link target"
    assert "alert(6)" in body, "the refused data: link lost its text"


def test_mermaid_blocks_become_pre_mermaid(tmp_path):
    page = """# Diagram

What it answers.

```mermaid
flowchart LR
    A["<script>alert(1)</script>"] --> B["b & c"]
```

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    block = re.search(r'<pre class="mermaid">(.*?)</pre>', html, re.S)
    assert block, "the mermaid block is not a <pre class=\"mermaid\">"
    text = block.group(1)
    assert text.strip().startswith("flowchart LR")
    assert "&lt;script&gt;" in text and "<script>" not in text
    assert "&amp;" in text, "the diagram's & is not escaped"
    assert '<pre class="code"><code class="language-mermaid">' not in html


def test_a_page_without_headings_breaks_nothing(tmp_path):
    """A page with no `# h1` still needs an anchor, or its navigation entry and
    its search hits point at an id that is nowhere in the document (round 1,
    Minor 5): the <section> carries the page id then."""
    html = _build(tmp_path, {"page.md": "Only a line of text, no heading at all.\n"})
    assert "Only a line of text" in html
    assert wiki.headings(html), "the index page lost its headings too"
    ids = _ids(html)
    assert "page" in ids, "the page without a heading has no jump target"
    nav = html[html.index('<nav id="toc"'):html.index("</nav>")]
    targets = re.findall(r'<a class="toc-(?:page|head)" href="#([^"]+)"', nav)
    assert "page" in targets
    for target in targets:
        assert target in ids, "the navigation jumps to #%s, which is nowhere" % target
    for record in _index_data(html):
        assert record["h"] in ids, "a search hit jumps nowhere: %s" % record


def test_a_picture_that_is_not_embedded_is_named_not_linked(tmp_path):
    """Round 1, Minor 7: a picture the build does not have must not become a
    relative <img src="../static/...">. Nothing carries static/ to the VM, so
    that src is a broken frame there - and the only resource in the file that
    is not inside it."""
    html = _build(tmp_path, {"page.md": "# P\n\nWhat it answers.\n\n"
                                        "![A shot](../static/missing.png)\n"})
    assert "missing.png" in html, "the missing picture is not even named"
    assert '<span class="no-image">' in html
    assert "../static/" not in html, "a relative path to a picture"
    for value in re.findall(r'\b(?:src|srcset|poster|data)="([^"]*)"', _no_mermaid(html)):
        assert value.startswith("data:"), "a resource outside the file: %s" % value[:60]


def test_headings_reports_level_id_and_text():
    html = wiki.render_markdown("# Title\n\n## Part `one`\n\n### Deep\n", {},
                                page="page.md")
    assert wiki.headings(html) == [
        (1, "page", "Title"), (2, "page--part-one", "Part one"),
        (3, "page--deep", "Deep")]


# --- The build ---------------------------------------------------------------


def test_the_search_index_keeps_names_whole(real_wiki):
    """Found while reading the built index: stripping every `*` and `_` out of a
    line turned `self_connect_retries` into "selfconnectretries" and `asm.*`
    into "asm.", so the names people actually search for were unfindable. The
    markers come off the way the renderer reads them, code spans first."""
    records = _index_data(real_wiki)
    for name in ["self_connect_retries", "write_failed", "raw_trimmed", "asm.*",
                 "TDC_RIZIN", "Hunt-Sleeping-Beacons"]:
        assert [r for r in records if name in r["t"]], "the index lost %s" % name
    assert [r for r in records if "**" in r["t"]] == [], "a bold marker in a hit"
    # Every page of the guide has lines in the index, and a long row is in it
    # whole: the rows of docs/api.md run past 1800 characters
    assert len({r["p"] for r in records}) == 15
    assert max(len(r["t"]) for r in records) <= wiki.MAX_SEARCH_LINE


def test_bold_around_a_code_span_is_bold(tmp_path):
    """The docs write **`make deploy-restart`**: the code span is taken out
    before the emphasis is read, so the `**` has to survive that."""
    html = wiki.render_markdown("**`make docs`** builds it.\n", {})
    assert "<strong><code>make docs</code></strong>" in html, html


def test_the_search_index_cannot_break_its_own_script(tmp_path):
    """Round 1, Important 1: a docs line with `<!--` on a page that also writes
    `<script` anywhere put both sequences verbatim into `const WIKI_INDEX`. The
    HTML tokenizer then enters script-data-double-escaped state, `</script>`
    stops closing the element, and every line of the wiki's own JavaScript -
    search, navigation marking, diagram zoom - is swallowed together with
    `</body></html>`. The bundle already had this guard; the index did not."""
    page = """# Comment

What it answers.

A line with an HTML comment opener <!-- in it.

And a line that writes <script somewhere on the same page.

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    literal = re.search(r"const WIKI_INDEX = (\[.*?\]);\n", html, re.S).group(1)
    assert "<" not in literal, "a raw < in the index literal: %r" % literal[
        max(0, literal.index("<") - 60):literal.index("<") + 60]
    assert "\\u003c" in literal, "the index does not escape its angle brackets"
    # The lines are still in the index, only their < is written as an escape
    records = _index_data(html)
    assert [r for r in records if "<!--" in r["t"]], "the comment line is not indexed"
    assert [r for r in records if "<script" in r["t"]], "the script line is not indexed"
    # and the document still closes itself
    assert html.rstrip().endswith("</body></html>")


def test_a_fence_without_a_language_closes_again(tmp_path):
    """Round 1, Important 2: the index's fence state machine stored "" for a
    bare ``` opener, which is falsy, so the closing fence opened a second block
    and every later line of the page was indexed raw - markdown markers and all.
    That is the regression test_the_search_index_keeps_names_whole exists for,
    and a raw `https://` in such a line would fail the no-network scan on a
    legitimate docs edit."""
    page = """# Fences

What it answers.

```
a plain block without a language
```

After the block a name like `self_connect_retries` and a link to
[the UI](http://localhost:9000) follow.

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    records = _index_data(html)
    after = [r for r in records if "self_connect_retries" in r["t"]]
    assert after, "the line after the block is not indexed"
    for record in after:
        assert "`" not in record["t"], "indexed raw, not as prose: %r" % record["t"]
        assert "](" not in record["t"], "indexed raw, not as prose: %r" % record["t"]
    # the block's own line stays as it stands, because code is not prose
    assert [r for r in records if r["t"] == "a plain block without a language"]


def test_a_fence_closes_the_way_the_renderer_closes_it(tmp_path):
    """Round 3: the index toggled on every ``` line, while _blocks closes a
    block only on a run at least as long as its opener and without a language.
    A ```` block holding a ``` line was therefore code in the page and prose
    from there on in the index - and the lines after it were indexed under the
    wrong state, raw markdown or escaped code. No page writes this today; the
    two sides agreeing is cheaper than the next person finding out.
    """
    page = """# Fences

What it answers.

````text
a block opened with four backticks
```
a line of three, which closes nothing
````

After it a name like `self_connect_retries` follows.

**Next:** [Index](README.md)
"""
    html = _build(tmp_path, {"page.md": page})
    records = _index_data(html)
    # The inner ``` line is content of the block, in the page and in the index
    body = html[html.index('data-page="page"'):]
    body = body[:body.index("</section>")]
    assert "a line of three, which closes nothing" in body
    assert [r for r in records if r["t"] == "a line of three, which closes nothing"]
    # and the line after the block is prose again, not raw code
    after = [r for r in records if "self_connect_retries" in r["t"]]
    assert after, "the line after the block is not indexed"
    for record in after:
        assert "`" not in record["t"], "indexed as code, not as prose: %r" % record["t"]


def test_the_wiki_is_written_whole_or_not_at_all(tmp_path, monkeypatch):
    """Round 4, Minor 8: the document was written straight over the output, so
    a full disk left a truncated wiki.html behind - and /api/wiki reports that
    file as present, the help links it, and on the VM it is the only
    documentation there is. The build writes beside the target and renames,
    which is atomic on every file system this runs on, and takes its temporary
    file with it when the write fails."""
    pages = {"page.md": "# P\n\nWhat it answers.\n\n**Next:** [Index](README.md)\n"}
    docs = _fixture_docs(tmp_path, pages)
    static = tmp_path / "static"
    static.mkdir()
    out = tmp_path / "wiki.html"
    whole = wiki.build_wiki(str(docs), str(static), MERMAID, str(out))
    assert out.read_text(encoding="utf-8") == whole

    real_open = open

    class Half(object):
        """A file that takes half of what it is given, then the disk is full."""

        def __init__(self, fh):
            self.fh = fh

        def write(self, text):
            self.fh.write(text[:len(text) // 2])
            raise IOError(28, "No space left on device")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()
            return False

    def failing(path, mode="r", *args, **kwargs):
        if "w" in mode:
            return Half(real_open(path, mode, *args, **kwargs))
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setitem(wiki.__dict__, "open", failing)
    with pytest.raises(IOError):
        wiki.build_wiki(str(docs), str(static), MERMAID, str(out))
    monkeypatch.undo()
    assert out.read_text(encoding="utf-8") == whole, \
        "a truncated wiki replaced the one that was there"
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("wiki")) \
        == ["wiki.html"], "the failed write left its temporary file behind"


def test_the_build_refuses_a_missing_or_changed_mermaid(tmp_path):
    docs = _fixture_docs(tmp_path, {"page.md": "# P\n\nWhat it answers.\n"})
    static = tmp_path / "static"
    static.mkdir()
    out = tmp_path / "wiki.html"
    missing = tmp_path / "nowhere" / "mermaid.min.js"
    with pytest.raises(wiki.WikiError) as err:
        wiki.build_wiki(str(docs), str(static), str(missing), str(out))
    assert "mermaid.min.js" in str(err.value) and wiki.MERMAID_VERSION in str(err.value)
    assert not out.exists(), "a wiki without its diagrams was written anyway"
    changed = tmp_path / "mermaid.min.js"
    changed.write_text("// not mermaid\n", encoding="utf-8")
    with pytest.raises(wiki.WikiError) as err:
        wiki.build_wiki(str(docs), str(static), str(changed), str(out))
    message = str(err.value)
    assert wiki.MERMAID_SHA256 in message and "SHA-256" in message
    assert not out.exists(), "a wiki with a foreign Mermaid was written anyway"


def test_the_footer_carries_the_build_date(tmp_path):
    before = datetime.datetime.utcnow() - datetime.timedelta(seconds=2)
    html = _build(tmp_path, {"page.md": "# P\n\nWhat it answers.\n"})
    after = datetime.datetime.utcnow() + datetime.timedelta(seconds=2)
    footer = html[html.index('<footer'):html.index("</footer>")]
    assert re.search(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\b", footer), footer
    # Genuinely UTC, not the host's clock with a UTC label on it (round 1,
    # Minor 4): a wiki built in Berlin used to be an hour ahead of itself.
    stamp = re.search(r'<time datetime="([^"]+)">', footer)
    assert stamp, footer
    built = datetime.datetime.strptime(stamp.group(1), "%Y-%m-%dT%H:%M:%SZ")
    assert before <= built <= after, \
        "the footer says %s, the build ran between %s and %s UTC" % (built, before, after)
    assert built.strftime("%Y-%m-%d %H:%M") + " UTC" in footer, \
        "the two stamps of the footer do not agree"
    short = None
    try:
        short = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                        cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover - no git
        pass
    if short:
        assert short in footer, "git is reachable but the footer has no commit"
    else:  # pragma: no cover - a source tree without git
        assert "commit" not in footer
    # Nothing about this machine: no local path, no host name
    assert ROOT not in html and str(tmp_path) not in html
    assert platform.node() not in html
    assert os.path.expanduser("~") not in html


def test_make_docs_is_the_entry_point_on_both_hosts():
    make = _read("Makefile")
    docs = make[make.index("\ndocs:"):]
    docs = docs[:docs.index("\n.PHONY")]
    assert "scripts/build-wiki.py" in docs
    assert "webui/static/wiki.html" in make
    assert ".PHONY: docs" in make
    assert "make docs" in make[:make.index(".DEFAULT_GOAL")], "make help forgets docs"
    # Round 4, Minor 9: the recipe ran `python3` outright, so a host whose
    # Python is on PATH as `python` got "make: python3: No such file or
    # directory" - a bare shell error about a name nobody typed, instead of the
    # generator's own messages. The interpreter is looked for and the failure
    # says what is missing.
    assert "command -v" in docs, \
        "the docs recipe does not look for an interpreter before running one"
    assert re.search(r"needs Python", docs), \
        "the docs recipe does not say what is wrong when there is no Python"
    assert "python" in re.findall(r"\bpython3?(?:\.\d+)?\b", docs), \
        "the docs recipe still knows only python3"
    ps1 = _read("make.ps1")
    assert "'docs'" in ps1[:ps1.index("# --- Configuration ---")], \
        "make.ps1 does not accept the docs target"
    branch = ps1[ps1.index("'docs' {"):]
    branch = branch[:branch.index("\n    '")]
    assert "scripts\\build-wiki.py" in branch or "scripts/build-wiki.py" in branch
    assert "make.ps1 docs" in ps1
    # The built file is generated, so it is not in the repository
    assert "webui/static/wiki.html" in _read(".gitignore")


def test_the_guide_says_where_the_parsers_limits_are_written_down():
    """Round 4, Minor 10: the markdown forms the generator deliberately refuses
    are written down in its own docstring, which nobody writing a docs page
    opens - so a page could use one and show it as text without anybody knowing
    where to look. docs/development.md names the list and where it is, and the
    count it quotes is checked against the list itself."""
    page = _read("docs", "development.md")
    assert "scripts/build-wiki.py" in page, \
        "docs/development.md does not name the generator"
    assert "refuses" in page, \
        "docs/development.md does not say that the parser refuses markdown forms"
    source = _read("scripts", "build-wiki.py")
    opens = source.index('"""')
    docstring = source[opens + 3:source.index('"""', opens + 3)]
    refused = re.findall(r"^  \* ", docstring, re.M)
    assert len(refused) == 11 and "eleven forms" in page, \
        "the generator refuses %d markdown forms; docs/development.md says " \
        "eleven - whichever moved, both have to agree" % len(refused)


def test_the_credits_name_the_vendored_mermaid_copy():
    """The first third-party file carried in this repository: the Credits table
    names it the way it names the tools, with its licence."""
    readme = _read("README.md")
    credits = readme[readme.index("## Credits"):readme.index("## License")]
    row = next((l for l in credits.splitlines() if "mermaid" in l.lower()), None)
    assert row, "the Credits do not name Mermaid"
    assert "MIT" in row and wiki.MERMAID_VERSION in row, row
    assert "mermaid-js/mermaid" in row, row
    licence = _read("scripts", "wiki", "mermaid-LICENSE")
    assert "MIT License" in licence and "Knut Sveidqvist" in licence


def test_the_generator_is_the_standard_library_only():
    """Python 3.9 on the host, no dependency: the VM builds nothing, but the
    generator stays as plain as everything else in scripts/."""
    source = _read("scripts", "build-wiki.py")
    imports = set(re.findall(r"^(?:import|from) ([\w.]+)", source, re.M))
    allowed = {"argparse", "base64", "datetime", "hashlib", "html", "json", "os",
               "re", "subprocess", "sys", "textwrap", "typing"}
    assert imports <= allowed, imports - allowed


# --- The way to the wiki: the route and the help -----------------------------
# The file is only of use to someone who finds it. The Web UI is where the
# people who need it are - on the VM it is the only place, because that machine
# has no network at all and no second browser tab to put a documentation site
# in.

WIKI_IN_UI = "/static/wiki.html"
NODE = shutil.which("node")


def _app_js_function(name):
    """Source of a top-level ``function name(...) {...}`` of app.js."""
    source = _read("webui", "static", "js", "app.js")
    m = re.search(r"^(?:async )?function %s\(" % re.escape(name), source, re.M)
    assert m, "%s is not a function of app.js" % name
    start = source.index("{", m.end())
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start():i + 1]
    raise AssertionError("unbalanced braces in %s" % name)


def _run_node(names, script):
    """Run those functions of app.js in Node and read back what they printed."""
    code = "\n".join(_app_js_function(n) for n in names) + "\n" + script
    out = subprocess.run([NODE, "-e", "require('vm').runInThisContext("
                          "require('fs').readFileSync(0, 'utf8'), {filename: '[eval]'});"],
                         input=code, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_wiki_route_says_whether_the_file_is_there(client, tdc, tmp_path, monkeypatch):
    """The help must neither promise a file that is not there nor hide an old
    one, so it asks the server: /api/wiki says whether webui/static/wiki.html
    exists and when it was last written.

    "Not there" is a normal answer, not an error: the file is 15 MB and
    git-ignored, so a fresh clone has none until someone runs `make docs`, and a
    VM deployed before that first build has none either. The date is the file's
    own mtime in UTC - a wiki is built once while the guide moves on, and
    nothing else in the UI would show its age.
    """
    missing = tmp_path / "nowhere" / "wiki.html"
    monkeypatch.setattr(tdc, "WIKI_FILE", str(missing))
    answer = client.get("/api/wiki")
    assert answer.status_code == 200
    assert answer.get_json() == {"present": False, "built": None}

    out = tmp_path / "wiki.html"
    out.write_text("<!DOCTYPE html>\n<html><body>a wiki</body></html>\n", encoding="utf-8")
    # A fixed moment, as UTC seconds: the stamp must not follow the host's zone
    # (the suite runs under TZ=UTC and under TZ=Europe/Berlin).
    when = calendar.timegm((2026, 3, 4, 5, 6, 7, 0, 0, 0))
    os.utime(str(out), (when, when))
    monkeypatch.setattr(tdc, "WIKI_FILE", str(out))
    answer = client.get("/api/wiki")
    assert answer.status_code == 200
    assert answer.get_json() == {"present": True, "built": "2026-03-04T05:06:07Z"}

    # A directory of that name is not a wiki either
    folder = tmp_path / "folder"
    folder.mkdir()
    monkeypatch.setattr(tdc, "WIKI_FILE", str(folder))
    assert client.get("/api/wiki").get_json() == {"present": False, "built": None}

    # The route is in the reference like every other one
    row = next((l for l in _read("docs", "api.md").splitlines() if "`/api/wiki`" in l), None)
    assert row and row.startswith("| GET "), "docs/api.md has no GET row for /api/wiki"
    assert "wiki.html" in row and "make docs" in row, row
    # Round 4, Important 4: the row said the route reports "when it was built",
    # which every deploy falsifies - app.py reports os.path.getmtime of the
    # copy, and task 6 reworded the help for exactly this reason. The API
    # reference is the contract for the `built` field, so a consumer writing a
    # staleness check against it inherits the defect. The row has to say what
    # the stamp is, that a deploy can renew it, and where the build stamp is.
    assert "when it was built" not in row, \
        "docs/api.md calls the file's mtime a build date: %s" % row
    assert re.search(r"last (?:modifi|writ)", row, re.I), \
        "the row does not say that `built` is the file's last modification: %s" % row
    assert "deploy" in row, \
        "the row does not say that a deploy can renew that date: %s" % row
    assert "footer" in row, \
        "the row does not say where the build stamp really is (the wiki's footer): %s" % row


def test_the_help_offers_the_wiki_or_says_how_to_build_it():
    """The help carries both states of the entry, and app.js shows the one the
    server reports: the link to /static/wiki.html with the file's date beside
    it, or the line that says `make docs` builds it.

    Neither is shown before the answer arrives. A link that is there before
    anybody asked would be a 404 on a machine without the file, and the build
    hint beside a wiki that is there would send a reader off to build what he
    is looking at.
    """
    help_html = _read("webui", "templates", "index.html")
    overview = help_html[help_html.index('id="help-overview"'):help_html.index('id="help-usage"')]
    assert 'href="%s"' % WIKI_IN_UI in overview, \
        "the help has no link to the wiki, and the help is where a reader looks"
    assert 'id="help-wiki-built"' in overview, "the link has no place for the file's date"
    assert "make docs" in overview, "nothing in the help says how to build the wiki"
    for element in ("help-wiki-link", "help-wiki-missing"):
        m = re.search(r'<p[^>]*\bid="%s"([^>]*)>' % element, overview)
        assert m, "the help has no %s" % element
        assert "hidden" in m.group(1), "%s is shown before /api/wiki answered" % element

    # Round 1, Important 1: the date is the file's mtime, and every deploy
    # writes the copy on the VM anew - so the help may not call it a build date.
    # A wiki built in March and deployed in November would read "Built
    # 2026-11-17 UTC, 0 days old", which is the silent staleness this entry
    # exists to prevent, in confident words.
    assert ">Built <span" not in overview and "Built <span" not in overview, \
        "the help calls the file's mtime a build date"
    assert "dated" in overview, "the help does not say what its date is the date of"
    # Round 4, Minor 7: "which a deploy renews" is true on the Vagrant and the
    # Hyper-V path, where the copy is stamped with the deploy's clock, and
    # false on the UTM path, which hands the copy the date of the file it came
    # from (scripts/deploy-utm.py, test_the_utm_deploy_keeps_the_date_of_every_file_it_copies).
    # The sentence may promise only what all three paths do.
    assert "deploy renews" not in overview, \
        "the help promises that every deploy renews the date; the UTM deploy keeps it"
    assert "a deploy can renew" in overview, \
        "the help does not say that a deploy may renew that date"
    assert "footer" in overview, \
        "the help does not say where the real build stamp is (the wiki's own footer)"
    # No date, no sentence about one (round 1, Minor 4): the whole clause is one
    # element, so nothing dangles when the stamp cannot be read
    m = re.search(r'<span[^>]*\bid="help-wiki-date"([^>]*)>', overview)
    assert m and "hidden" in m.group(1), "the date clause is not one element that can be hidden"
    assert overview.index('id="help-wiki-date"') < overview.index('id="help-wiki-built"'), \
        "the place for the date is not inside the sentence about it"

    js = _read("webui", "static", "js", "app.js")
    assert "'/api/wiki'" in js, "nothing in app.js asks /api/wiki"
    init = js[js.index("// --- Initialization ---"):]
    init = init[:init.index("\n});")]
    assert "initHelpWiki()" in init, \
        "the wiki is not looked for when the page starts"
    # A browser on the VM holds the old app.js and style sheet until the query
    # string changes, and then the entry would never be filled in. Round 4,
    # Minor 3: this used to be a list of three superseded `?v=` values, which
    # is a snapshot and not an invariant - the next forgotten bump passes it
    # just as well. What this suite can hold honestly is that the references
    # carry a version at all; the bump itself is pinned by the suite of
    # whichever change needed it (tests/test_logs_ui.py, tests/test_rizin_ui.py
    # and the others each hold the value they superseded).
    assert re.search(r'/static/js/app\.js\?v=\d+', help_html), \
        "app.js is loaded without a version, so a VM browser keeps the old one forever"
    assert re.search(r'/static/css/style\.css\?v=\d+', help_html), \
        "style.css is loaded without a version"


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_the_help_shows_the_date_of_the_file_and_its_age():
    """The date beside the link is the one the route reports, written the way
    the wiki's own footer writes it (2026-03-04 05:06 UTC), with the age in
    days after it - the reason the spec gives for the date in the first place:
    a wiki is built once and then lies there while the guide moves on.

    The stamp is cut out of the ISO string, never parsed into a local time: a
    file built at 05:06 UTC must not read 06:06 to a browser in Berlin.
    """
    labels, states = _run_node(["wikiBuiltLabel", "renderWikiState"], """
const now = Date.parse('2026-03-16T05:06:07Z');
const labels = [
    wikiBuiltLabel('2026-03-04T05:06:07Z', now),
    wikiBuiltLabel('2026-03-15T23:00:00Z', now),
    wikiBuiltLabel('2026-03-16T04:00:00Z', now),
    wikiBuiltLabel('2026-03-15T05:06:07Z', now),
    wikiBuiltLabel('nonsense', now),
];
const els = {};
for (const id of ['help-wiki', 'help-wiki-link', 'help-wiki-missing', 'help-wiki-date',
                  'help-wiki-built'])
    els[id] = { id, hidden: true, textContent: '' };
globalThis.document = { getElementById: id => els[id] || null };
const seen = () => ({ box: els['help-wiki'].hidden, link: els['help-wiki-link'].hidden,
                      missing: els['help-wiki-missing'].hidden,
                      date: els['help-wiki-date'].hidden,
                      built: els['help-wiki-built'].textContent });
const states = [];
renderWikiState({ present: true, built: '2026-03-04T05:06:07Z' });
states.push(seen());
renderWikiState({ present: false, built: null });
states.push(seen());
renderWikiState(null);
states.push(seen());
renderWikiState({ present: true, built: 'nonsense' });
states.push(seen());
console.log(JSON.stringify([labels, states]));
""")
    assert labels[0].startswith("2026-03-04 05:06 UTC"), labels[0]
    assert "12 days" in labels[0], labels[0]
    # Younger than a day: the stamp alone, no age to report yet
    assert labels[1] == "2026-03-15 23:00 UTC" and labels[2] == "2026-03-16 04:00 UTC", labels[1:3]
    assert "1 day" in labels[3] and "1 days" not in labels[3], labels[3]
    assert labels[4] == "", "a stamp the server never sends must not become a date: %r" % labels[4]

    present, absent, unknown, unreadable = states
    assert {k: present[k] for k in ("box", "link", "missing", "date")} == \
        {"box": False, "link": False, "missing": True, "date": False}, present
    # renderWikiState dates the file against the browser's clock, so only its
    # shape is fixed here; wikiBuiltLabel above holds the arithmetic.
    assert present["built"].startswith("2026-03-04 05:06 UTC \u00b7 ") and \
        present["built"].endswith("days old"), present["built"]
    for state in (absent, unknown):
        assert state == {"box": False, "link": True, "missing": False,
                         "date": True, "built": ""}, state
    # Round 1, Minor 4: a present wiki whose stamp cannot be read showed the
    # sentence with an empty date in it ("The file here is dated  - that is ...")
    assert unreadable == {"box": False, "link": False, "missing": True,
                          "date": True, "built": ""}, unreadable


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_the_help_ignores_an_answer_that_is_not_the_routes_answer():
    """Round 1, Minor 5: an `ok` response whose body is not the route's shape -
    {} from a misrouted request, an error object from something in front of
    Flask - was read as present: false, and the help then told a reader to build
    a file he may well have had. No usable answer is now the same as no answer:
    the entry stays hidden and says nothing.
    """
    states = _run_node(["wikiBuiltLabel", "renderWikiState", "initHelpWiki"], """
const els = {};
for (const id of ['help-wiki', 'help-wiki-link', 'help-wiki-missing', 'help-wiki-date',
                  'help-wiki-built'])
    els[id] = { id, hidden: true, textContent: '' };
globalThis.document = { getElementById: id => els[id] || null };
const reset = () => { for (const id in els) { els[id].hidden = true; els[id].textContent = ''; } };
const seen = () => ({ box: els['help-wiki'].hidden, link: els['help-wiki-link'].hidden,
                      missing: els['help-wiki-missing'].hidden,
                      built: els['help-wiki-built'].textContent });
const answers = {
    object_without_present: { ok: true, json: async () => ({}) },
    error_body: { ok: true, json: async () => ({ error: 'Host not allowed' }) },
    a_string: { ok: true, json: async () => 'wiki' },
    null_body: { ok: true, json: async () => null },
    present_not_a_boolean: { ok: true, json: async () => ({ present: 'yes', built: null }) },
    server_error: { ok: false, status: 500, json: async () => ({}) },
    broken_json: { ok: true, json: async () => { throw new Error('not json'); } },
    no_server: null,
    the_route: { ok: true, json: async () => ({ present: true, built: '2026-03-04T05:06:07Z' }) },
};
(async () => {
    const out = {};
    for (const [name, answer] of Object.entries(answers)) {
        reset();
        globalThis.fetch = async () => { if (!answer) throw new Error('failed to fetch'); return answer; };
        await initHelpWiki();
        out[name] = seen();
    }
    console.log(JSON.stringify(out));
})();
""")
    hidden = {"box": True, "link": True, "missing": True, "built": ""}
    for name in ("object_without_present", "error_body", "a_string", "null_body",
                 "present_not_a_boolean", "server_error", "broken_json", "no_server"):
        assert states[name] == hidden, \
            "%s: the help said something it could not know: %s" % (name, states[name])
    # and the route's own answer still arrives
    assert states["the_route"]["box"] is False and states["the_route"]["link"] is False, \
        states["the_route"]
    assert states["the_route"]["built"].startswith("2026-03-04 05:06 UTC"), states["the_route"]
