#!/usr/bin/env python3
"""Build the offline wiki: docs/*.md -> webui/static/wiki.html.

The VM has no network: nobody working there can open GitHub or a documentation
site, so the whole guide is turned into one self-contained HTML file that opens
as a loose file (`open webui/static/wiki.html`) as well as over the Web UI. That
rules out an ES module, `fetch` and every resource over http(s): the screenshots
go in as `data:` URIs, the search index is data in the document, and the
diagrams are drawn by a pinned copy of Mermaid that is embedded with the page.

Python 3.9, standard library only - the host builds the file (`make docs`,
`.\\make.ps1 docs`), the VM only receives it.

Public functions:
    page_order(index_text)                  the pages, in the index's order
    render_markdown(text, images, page="")  one page of markdown as HTML
    headings(html)                          (level, id, text) of every heading
    build_wiki(docs_dir, static_dir, mermaid_path, out_path)

What this parser deliberately does NOT carry (no page of the guide uses any of
it, and a parser that grows features nobody reads is worse than a short one).
Writing one of these into a docs page shows the line as it stands, or renders
it slightly wrong - so use the form on the right instead:

  * setext headings (`Title` over `=====`)        -> `# Title`
  * `~~~` fences, including `~~~mermaid`          -> ``` fences (a ~~~ block
                                                     would be lost as text)
  * four-space indented code blocks               -> a ``` fence with a language
  * brackets inside a link text,
    `[text [with] brackets](url)`                 -> no brackets in link text
  * single-quoted image titles, `![a](x.png 'T')` -> no title, or "T" in quotes
  * two trailing spaces as a hard line break      -> a blank line, or a list
  * entity references (`&mdash;`, `&amp;`)        -> the character itself
  * task list markers (`- [ ]`, `- [x]`)          -> a plain list
  * the table alignment row (`|:--|--:|`)         -> `|---|---|` (alignment is
                                                     ignored, not refused)
  * an unbalanced backtick in a table cell        -> close every code span, or
                                                     its row merges cells
  * `***both***` renders as mis-nested tags       -> `**bold** and *italic*`
"""

import argparse
import base64
import datetime
import hashlib
import html as html_lib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TITLE = "Transportable Detonation Chamber"
SUBTITLE = "Offline wiki"
REPO_URL = "https://github.com/BenjiTrapp/transportable-detonation-chamber"
REPO_BLOB = REPO_URL + "/blob/main/"

# The pinned Mermaid copy. Version 11 ships as an ES module only, which a
# browser refuses to load from file://, so this is Mermaid 10 as a UMD bundle.
# Checksum and version are written down here: `make docs` refuses to build a
# wiki whose diagrams would be dead text (see read_mermaid).
MERMAID_VERSION = "10.9.3"
MERMAID_SHA256 = "5a8ec91820bd55afef049068489369910e5d6ce70c8103952f27e29d3e76e8bc"
MERMAID_SOURCE = "https://cdn.jsdelivr.net/npm/mermaid@%s/dist/mermaid.min.js" % MERMAID_VERSION
MERMAID_SCRIPT_OPEN = '<script id="mermaid-bundle" data-version="%s">' % MERMAID_VERSION

# The demo video is 10 MB and no deploy path carries static/ to the VM: the wiki
# names it and links it into the repository instead of showing a dead frame.
DEMO_GIF = "static/demo.gif"

# What a link out of docs/ costs the reader this file was built for. The wiki
# rewrites `../README.md` into a URL on github.com, which the VM cannot open at
# all - so every rewritten link says so, in the words the demo-video note uses.
NETWORK_NOTE = "needs network access, which the VM does not have"

MAX_SEARCH_LINE = 300
SEARCH_OVERLAP = 60


class WikiError(Exception):
    """The build cannot produce an honest wiki (reported, nothing written)."""


# --- Identifiers -------------------------------------------------------------


def slug(text):
    """A heading's anchor, the way GitHub makes it.

    The docs link their own headings (`](#own-dashboards)`), so the wiki has to
    produce the same anchors: inline markup is dropped, then everything that is
    not a word character, a space or a hyphen - including the em dash and the
    ampersand of "Dashboard & Alerts Charts" - and the spaces that are left
    become hyphens (two of them where a dropped character sat between spaces).
    """
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links and images
    text = text.replace("`", "").replace("**", "").replace("__", "")
    text = re.sub(r"[*_]", "", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def page_id(name):
    """The id of a page: its file name without .md, the index as "readme"."""
    stem = os.path.basename(name)
    if stem.lower().endswith(".md"):
        stem = stem[:-3]
    return slug(stem)


def heading_id(page, text):
    """The id of a heading inside a page: "rizin--sessions"."""
    anchor = slug(text)
    prefix = page_id(page) if page else ""
    if not prefix:
        return anchor
    return prefix if not anchor else "%s--%s" % (prefix, anchor)


def page_order(index_text):
    """The pages of the guide, in the order docs/README.md links them.

    The index itself comes first - it is the page a reader lands on. Links to
    the repository (`../README.md`) and to the web are not pages of the guide.
    """
    order = ["README.md"]
    for target in re.findall(r"\]\(([A-Za-z0-9_-]+\.md)(?:#[^)]*)?\)", index_text):
        if target not in order:
            order.append(target)
    return order


# --- Markdown ----------------------------------------------------------------

_LIST = re.compile(r"^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$")
_FENCE = re.compile(r"^(\s{0,3})(`{3,})\s*([\w+.-]*)\s*$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_RULE = re.compile(r"^\s{0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$")
_DELIM = re.compile(r"^\s*\|?(?:\s*:?-+:?\s*\|)+\s*:?-*:?\s*\|?\s*$")
# A link may point at the web, at an anchor or at a path; `data:` is what an
# embedded picture needs in a src, not what a link needs in an href, and
# `javascript:` is refused outright.
_SAFE_SCHEME = re.compile(r"^(?:https?:|mailto:|#|/)", re.I)


class _Ctx(object):
    """What a render needs besides the lines: the pictures and the page."""

    def __init__(self, images, page):
        self.images = images or {}
        self.page = page
        self.used_ids = {}

    def heading_id(self, text, level=2):
        base = page_id(self.page) if (level == 1 and self.page) else heading_id(self.page, text)
        seen = self.used_ids.get(base, 0)
        self.used_ids[base] = seen + 1
        return base if not seen else "%s-%d" % (base, seen + 1)


def esc(text):
    """Markdown never becomes live HTML: a <script> in the source stays text."""
    return html_lib.escape(text, quote=True)


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _link_target(url, page):
    """Where a link of the guide points inside one file.

    A page of the guide becomes its jump target, an anchor is prefixed with the
    page it stands on, a path out of docs/ becomes a link into the repository on
    the web, and a scheme that could run code (`javascript:`) is refused.
    """
    page_link = re.match(r"^([A-Za-z0-9_-]+)\.md(?:#(.*))?$", url)
    if page_link:
        return "#" + heading_id(page_link.group(1) + ".md", page_link.group(2) or "")
    if url.startswith("#"):
        return "#" + heading_id(page, url[1:]) if page else url
    out_of_docs = re.match(r"^\.\./([^#]*)(#.*)?$", url)
    if out_of_docs:
        return REPO_BLOB + out_of_docs.group(1) + (out_of_docs.group(2) or "")
    if _SAFE_SCHEME.match(url):
        return url
    if ":" in url.split("/")[0]:
        return None  # javascript:, vbscript:, data:text/html, ...
    return url


_CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)


def _take_code_spans(text):
    """(text with code spans as markers, the spans) - their content is literal."""
    spans = []

    def take(m):
        spans.append(m.group(2))
        return "\x00%d\x00" % (len(spans) - 1)

    return _CODE_SPAN.sub(take, text), spans


def _put_code_spans(text, spans, wrap):
    return re.sub(r"\x00(\d+)\x00", lambda m: wrap(spans[int(m.group(1))]), text)


def _inline(text, ctx):
    """The inline markup of one run of text.

    Code spans are taken out first and put back at the end, so `*` or `_`
    inside them is never emphasis - and so emphasis around one still works
    (`**`make docs`**` is bold code, which the docs write).
    """
    marked, spans = _take_code_spans(text)
    rendered = _inline_markup(esc(marked), ctx)
    return _put_code_spans(rendered, spans, lambda s: "<code>%s</code>" % esc(s))


def _image(m, ctx):
    alt = m.group(1)
    name = os.path.basename(m.group(2).split("#")[0])
    data = ctx.images.get(name)
    if data:
        return '<img src="%s" alt="%s" loading="lazy">' % (data, alt)
    # Not embedded: say which picture is missing instead of a broken frame
    return '<span class="no-image">[%s: %s]</span>' % (esc(name), alt)


def _inline_markup(text, ctx):
    text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\)",
                  lambda m: _image(m, ctx), text)

    def link(m):
        target = _link_target(html_lib.unescape(m.group(2)), ctx.page)
        if target is None:
            return "%s (%s)" % (m.group(1), m.group(2))  # refused, kept visible
        external = target.startswith("http")
        extra = ' target="_blank" rel="noopener"' if external else ""
        # A path out of docs/ became a URL on github.com: on the VM that is a
        # dead end, and the reader has to be told before the click, not after.
        note = ('<span class="net-note"> (%s)</span>' % NETWORK_NOTE
                if target.startswith(REPO_BLOB) else "")
        return '<a href="%s"%s>%s</a>%s' % (esc(target), extra, m.group(1), note)

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text, flags=re.S)
    text = re.sub(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", r"<strong>\1</strong>", text, flags=re.S)
    text = re.sub(r"(?<![\w*])__(?=\S)(.+?)(?<=\S)__(?![\w*])", r"<strong>\1</strong>", text, flags=re.S)
    text = re.sub(r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])", r"<em>\1</em>", text)
    text = re.sub(r"(?<![\w_])_(?=\S)([^_\n]+?)(?<=\S)_(?![\w_])", r"<em>\1</em>", text)
    text = re.sub(r"~~(?=\S)(.+?)(?<=\S)~~", r"<del>\1</del>", text, flags=re.S)
    return text


def _code_block(body, lang):
    if lang.lower() == "mermaid":
        return '<pre class="mermaid">\n%s\n</pre>' % esc(body)
    attr = ' class="language-%s"' % esc(lang) if lang else ""
    return '<pre class="code"><code%s>%s</code></pre>' % (attr, esc(body))


def _starts_block(line):
    """Whether a line ends the paragraph above it."""
    if not line.strip():
        return True
    if _HEADING.match(line) or _FENCE.match(line) or _RULE.match(line):
        return True
    if line.lstrip().startswith(">"):
        return True
    if _LIST.match(line) and _indent(line) == 0:
        return True
    return False


def _blocks(lines, ctx):
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        fence = _FENCE.match(line)
        if fence:
            ticks, lang = fence.group(2), fence.group(3)
            body = []
            i += 1
            closing = re.compile(r"^\s{0,3}`{%d,}\s*$" % len(ticks))
            while i < len(lines) and not closing.match(lines[i]):
                body.append(lines[i])
                i += 1
            i += 1  # the closing fence, or the end of the page
            out.append(_code_block("\n".join(body), lang))
            continue
        head = _HEADING.match(line)
        if head:
            level = len(head.group(1))
            text = head.group(2)
            out.append('<h%d id="%s">%s</h%d>'
                       % (level, ctx.heading_id(text, level), _inline(text, ctx), level))
            i += 1
            continue
        if _RULE.match(line):
            out.append("<hr>")
            i += 1
            continue
        if line.lstrip().startswith(">"):
            quoted = []
            while i < len(lines) and lines[i].lstrip().startswith(">"):
                quoted.append(re.sub(r"^\s{0,3}>\s?", "", lines[i]))
                i += 1
            out.append("<blockquote>%s</blockquote>" % _blocks(quoted, ctx))
            continue
        if _LIST.match(line):
            html, i = _list(lines, i, ctx)
            out.append(html)
            continue
        if "|" in line and i + 1 < len(lines) and _DELIM.match(lines[i + 1]):
            html, i = _table(lines, i, ctx)
            out.append(html)
            continue
        para = [line]
        i += 1
        while i < len(lines) and not _starts_block(lines[i]):
            if "|" in lines[i] and i + 1 < len(lines) and _DELIM.match(lines[i + 1]):
                break
            para.append(lines[i])
            i += 1
        out.append("<p>%s</p>" % _inline("\n".join(para), ctx))
    return "".join(out)


def _list(lines, start, ctx):
    """One list, with the lists and blocks nested inside its items."""
    first = _LIST.match(lines[start])
    base = len(first.group(1))
    ordered = first.group(2)[0].isdigit()
    items = []
    i = start
    while i < len(lines):
        m = _LIST.match(lines[i])
        if not m or len(m.group(1)) > base + 1 or len(m.group(1)) < base:
            break
        if m.group(2)[0].isdigit() != ordered:
            break
        item = [m.group(3)]
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if not nxt.strip():
                deeper = (i + 1 < len(lines) and lines[i + 1].strip()
                          and _indent(lines[i + 1]) >= base + 2)
                if not deeper:
                    break
                item.append("")
                i += 1
                continue
            if _indent(nxt) >= base + 2:
                item.append(nxt[base + 2:])
                i += 1
                continue
            if not _LIST.match(nxt) and not _starts_block(nxt) and _indent(nxt) > base:
                item.append(nxt.lstrip())
                i += 1
                continue
            break
        items.append(item)
    body = "".join("<li>%s</li>" % _item(item, ctx) for item in items)
    tag = "ol" if ordered else "ul"
    return "<%s>%s</%s>" % (tag, body, tag), i


def _item(lines, ctx):
    """The content of one list item: tight, so a plain item carries no <p>."""
    html = _blocks(lines, ctx)
    if html.startswith("<p>"):
        end = html.index("</p>")
        html = html[3:end] + html[end + 4:]
    return html


def _cells(line):
    """The cells of a table row: a `|` inside a code span or escaped stays."""
    cells = []
    buf = []
    in_code = False
    j = 0
    while j < len(line):
        char = line[j]
        if char == "\\" and j + 1 < len(line) and line[j + 1] == "|":
            buf.append("|")
            j += 2
            continue
        if char == "`":
            in_code = not in_code
        if char == "|" and not in_code:
            cells.append("".join(buf))
            buf = []
            j += 1
            continue
        buf.append(char)
        j += 1
    cells.append("".join(buf))
    if cells and not cells[0].strip():
        cells.pop(0)
    if cells and not cells[-1].strip():
        cells.pop()
    return [c.strip() for c in cells]


def _table(lines, start, ctx):
    header = _cells(lines[start])
    i = start + 2
    rows = []
    while i < len(lines) and "|" in lines[i] and lines[i].strip():
        rows.append(_cells(lines[i]))
        i += 1
    out = ["<table><thead><tr>"]
    out += ["<th>%s</th>" % _inline(c, ctx) for c in header]
    out.append("</tr></thead><tbody>")
    for row in rows:
        # A row with more cells than the header keeps them: a lost cell would be
        # content silently gone.
        row = row + [""] * (len(header) - len(row))
        out.append("<tr>" + "".join("<td>%s</td>" % _inline(c, ctx) for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out), i


def render_markdown(text, images, page=""):
    """One page of markdown as HTML. Pure: `images` maps file names to data URIs.

    Carries headings, paragraphs, lists (nested too), fenced code blocks with a
    language, inline code, bold, italic, links, images, tables, blockquotes,
    horizontal rules and ```mermaid blocks. A line it does not know stays
    readable as text instead of being swallowed, and nothing in the source can
    become live HTML.
    """
    lines = text.replace("\r\n", "\n").replace("\t", "    ").split("\n")
    return _blocks(lines, _Ctx(images, page))


def headings(html):
    """(level, id, text) of every heading of a rendered page or document."""
    found = []
    for m in re.finditer(r'<h([1-6]) id="([^"]+)">(.*?)</h\1>', html, re.S):
        text = html_lib.unescape(re.sub(r"<[^>]+>", "", m.group(3))).strip()
        found.append((int(m.group(1)), m.group(2), text))
    return found


# --- The search index --------------------------------------------------------


def _plain(line):
    """One markdown line as the text a reader sees, for the search index.

    The markers come off the way the renderer reads them, not by deleting every
    `*` and `_`: `self_connect_retries` and `asm.*` are names people search
    for, and stripping the characters out of them would hide the line.
    """
    line = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", line)
    line = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", line)
    line = re.sub(r"^\s*>+\s*", "", line)
    line = re.sub(r"^\s*#+\s*", "", line)
    marked, spans = _take_code_spans(line)
    marked = re.sub(r"\*\*(.+?)\*\*", r"\1", marked)
    marked = marked.replace("**", "")  # a bold span wrapped over two lines
    marked = re.sub(r"(?<![\w*])\*(?=\S)([^*]+?)(?<=\S)\*(?![\w*])", r"\1", marked)
    marked = re.sub(r"(?<![\w_])_(?=\S)([^_]+?)(?<=\S)_(?![\w_])", r"\1", marked)
    line = _put_code_spans(marked, spans, lambda s: s)
    line = re.sub(r"^\s*\|\s*|\s*\|\s*$", "", line)
    line = line.replace("|", " ")
    line = re.sub(r"^\s*[-+*]\s+", "", line)
    return re.sub(r"\s+", " ", line).strip()


def _chunks(text):
    """A long line as overlapping pieces, so no word is past the index's reach.

    The rows of the API reference run to 1800 characters; cutting them at the
    first 300 would make their second half unsearchable.
    """
    if len(text) <= MAX_SEARCH_LINE:
        return [text]
    pieces = []
    step = MAX_SEARCH_LINE - SEARCH_OVERLAP
    for start in range(0, len(text), step):
        piece = text[start:start + MAX_SEARCH_LINE]
        if piece.strip():
            pieces.append(piece)
        if start + MAX_SEARCH_LINE >= len(text):
            break
    return pieces


def search_records(name, title, text):
    """The search index of one page: every text line with its heading.

    The whole index is data in the document, so the search runs in the browser
    with no server behind it.
    """
    records = []
    seen = set()
    heading_text = title
    anchor = page_id(name)
    fence = None
    ticks = 0
    for line in text.replace("\r\n", "\n").split("\n"):
        fenced = _FENCE.match(line)
        if fenced:
            # "is not None", not truthiness: a bare ``` opener has no language,
            # and "" would read as "no fence open" - the closing fence would
            # then open a second block and index the rest of the page raw.
            if fence is None:
                fence, ticks = fenced.group(3).lower(), len(fenced.group(2))
            elif len(fenced.group(2)) >= ticks and not fenced.group(3):
                # Closed the way _blocks closes it: at least as many backticks
                # as the opener and no language. A ```` block holding a ```
                # line stays one block here as it does in the rendered page -
                # otherwise the index would read the rest of the page as code
                # (or as prose) while the page shows the other.
                fence, ticks = None, 0
            continue
        if fence == "mermaid":
            continue  # a diagram's node labels are not prose
        head = _HEADING.match(line) if fence is None else None
        if head:
            # Only outside a fence: a YAML or PowerShell block is full of `#`
            # comments, and reading one as a heading both drops the line from
            # the index ("Enable Hyper-V", "ipconfig") and files the lines
            # after it under a label that is no section - a `##` comment even
            # produced an anchor that is nowhere in the document, so the hit
            # jumped nowhere. Inside a fence the line falls through to the
            # code path below instead.
            heading_text = re.sub(r"[`*]", "", head.group(2)).strip()
            anchor = (page_id(name) if len(head.group(1)) == 1
                      else heading_id(name, head.group(2)))
            continue
        if _DELIM.match(line):
            continue
        plain = _plain(line) if fence is None else line.strip()
        for piece in _chunks(plain):
            if len(piece) < 3:
                continue
            key = (anchor, piece)
            if key in seen:
                continue
            seen.add(key)
            records.append({"p": page_id(name), "pt": title, "h": anchor,
                            "ht": heading_text, "t": piece})
    return records


# --- The ingredients of the file ---------------------------------------------


def embed_images(static_dir):
    """Every PNG of static/ as a `data:` URI, by file name."""
    images = {}
    if not os.path.isdir(static_dir):
        return images
    for name in sorted(os.listdir(static_dir)):
        if not name.lower().endswith(".png"):
            continue
        with open(os.path.join(static_dir, name), "rb") as fh:
            raw = fh.read()
        images[name] = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    return images


def read_mermaid(path):
    """The pinned Mermaid bundle, or a WikiError saying what to do.

    A wiki whose diagrams are dead text is worse than no wiki: the build stops
    when the copy is missing or is not the version this generator was written
    against.
    """
    if not os.path.isfile(path):
        raise WikiError(
            "the pinned Mermaid copy is missing: %s\n"
            "  the wiki embeds mermaid@%s (UMD) so the diagrams are drawn without a network.\n"
            "  put the bundle of %s at scripts/wiki/mermaid.min.js (SHA-256 %s) and build again."
            % (path, MERMAID_VERSION, MERMAID_SOURCE, MERMAID_SHA256))
    with open(path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != MERMAID_SHA256:
        raise WikiError(
            "the pinned Mermaid copy is not the one this generator knows:\n"
            "  file     %s\n  SHA-256  %s\n  expected %s (mermaid@%s, UMD)\n"
            "  restore the pinned bundle from %s, or update version and checksum in "
            "scripts/build-wiki.py after checking the new one renders from file://."
            % (os.path.basename(path), digest, MERMAID_SHA256, MERMAID_VERSION, MERMAID_SOURCE))
    text = raw.decode("utf-8")
    # Nothing in the bundle may close the <script> that carries it. Both
    # sequences sit inside string literals of this version (checked against the
    # checksum above), where the backslash is a no-op escape.
    return text.replace("</script", "<\\/script").replace("<!--", "<\\!--")


def short_commit():
    """The short commit id of this repository, or "" when git is not reachable."""
    try:
        out = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                      stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    commit = out.decode("ascii", "replace").strip()
    return commit if re.match(r"^[0-9a-f]{7,40}$", commit) else ""


def _footer(built_at, commit):
    """The build date in UTC, the commit when git is reachable - nothing else.

    No local path and no machine name: the file travels to the VM and into the
    repository's issues.
    """
    parts = ['Built <time datetime="%s">%s UTC</time>'
             % (built_at.strftime("%Y-%m-%dT%H:%M:%SZ"), built_at.strftime("%Y-%m-%d %H:%M"))]
    if commit:
        parts.append("commit <code>%s</code>" % commit)
    parts.append("diagrams by Mermaid %s (MIT)" % MERMAID_VERSION)
    parts.append("%s &mdash; built with <code>make docs</code>" % TITLE)
    return '<footer class="wiki-footer">%s</footer>' % " &middot; ".join(parts)


def _demo_note():
    """The demo video: named, linked into the repository, never embedded."""
    return (
        '<p class="note"><strong>The demo video is not in this file.</strong> '
        '<code>%s</code> is a 10 MB GIF and no deploy path carries <code>static/</code> '
        'to the VM, so the wiki names it instead of showing a dead frame: '
        '<a href="%s%s" target="_blank" rel="noopener">watch it in the repository</a> '
        '&mdash; that link %s. '
        'Every still of it is in <a href="#web-ui">Web UI</a>.</p>'
        % (DEMO_GIF, REPO_BLOB, DEMO_GIF, NETWORK_NOTE))


def _nav(pages):
    """The navigation: the pages in the index's order, each with its ## level."""
    out = ['<nav id="toc" aria-label="Contents"><ul class="toc">']
    for page in pages:
        out.append('<li class="toc-item"><a class="toc-page" href="#%s" data-target="%s">%s</a>'
                   % (page["id"], page["id"], esc(page["title"])))
        subs = [(hid, text) for level, hid, text in page["headings"] if level == 2]
        if subs:
            out.append('<ul class="toc-subs">')
            for hid, text in subs:
                out.append('<li><a class="toc-head" href="#%s" data-target="%s">%s</a></li>'
                           % (hid, hid, esc(text)))
            out.append("</ul>")
        out.append("</li>")
    out.append("</ul></nav>")
    return "".join(out)


def _style():
    """The Cyberpunk theme's palette and fonts, code blocks as in the Web UI."""
    return """
:root {
  --cp-bg: #0b0716; --cp-bar-top: #170e2c; --cp-bar-bottom: #120a22;
  --cp-card: #140d24; --cp-raised: #1b1232; --cp-line: #251a3d;
  --cp-text: #f3eefc; --cp-text-muted: #c9bfe3; --cp-text-dim: #8a7fb0;
  --cp-magenta: #ff4fd8; --cp-cyan: #37e0ff; --cp-green: #39d98a;
  --cp-gold: #ffd060; --cp-amber: #ffb000; --cp-red: #ff3b3b;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --font-sans: system-ui, -apple-system, "Segoe UI", sans-serif;
  --radius: 6px;
  --nav-width: 310px;
}
* { box-sizing: border-box; }
/* No smooth scrolling: a jump from the index to the last page crosses tens of
   thousands of pixels in this one document, and animating that is slower than
   it is pretty. */
body {
  margin: 0; background: var(--cp-bg); color: var(--cp-text);
  font-family: var(--font-sans); font-size: 15px; line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--cp-cyan); text-decoration: none; }
a:hover { color: var(--cp-magenta); text-decoration: underline; }

/* --- The drawer on the left --- */
.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: var(--nav-width);
  background: linear-gradient(180deg, var(--cp-bar-top), var(--cp-bar-bottom));
  border-right: 1px solid var(--cp-line); display: flex; flex-direction: column;
  z-index: 10;
}
.brand { padding: 16px 18px 10px; border-bottom: 1px solid var(--cp-line); }
.brand b {
  display: block; font-family: var(--font-mono); font-size: 12px;
  letter-spacing: .12em; text-transform: uppercase;
  background: linear-gradient(90deg, var(--cp-gold), var(--cp-amber) 45%, var(--cp-red));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.brand span {
  display: block; margin-top: 4px; font-family: var(--font-mono);
  font-size: 10px; letter-spacing: .18em; text-transform: uppercase;
  color: var(--cp-text-dim);
}
.search-box { padding: 12px 14px; border-bottom: 1px solid var(--cp-line); }
#search {
  width: 100%; padding: 8px 10px; background: rgba(11, 7, 22, .9);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  color: var(--cp-text); font-family: var(--font-mono); font-size: 12px;
}
#search:focus { outline: none; border-color: var(--cp-magenta); box-shadow: 0 0 10px rgba(255, 79, 216, .25); }
.search-hint { margin: 6px 2px 0; font-family: var(--font-mono); font-size: 10px; color: var(--cp-text-dim); }
.scroller { overflow-y: auto; flex: 1; padding: 10px 0 24px; }
.toc, .toc-subs { list-style: none; margin: 0; padding: 0; }
.toc-page, .toc-head {
  display: block; padding: 5px 16px; border-left: 2px solid transparent;
  color: var(--cp-text-muted); text-decoration: none;
}
.toc-page {
  font-family: var(--font-mono); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--cp-text); margin-top: 8px;
}
.toc-head { font-size: 13px; padding-left: 28px; color: var(--cp-text-dim); }
.toc-page:hover, .toc-head:hover { color: var(--cp-cyan); text-decoration: none; background: rgba(55, 224, 255, .06); }
.toc-page.active, .toc-head.active {
  color: var(--cp-magenta); border-left-color: var(--cp-magenta);
  background: rgba(255, 79, 216, .08);
}
.toc-item.collapsed .toc-subs { display: none; }

/* --- The hits of a search --- */
#results { display: none; padding: 6px 0 10px; }
#results.open { display: block; }
.hit {
  display: block; width: 100%; text-align: left; background: none; border: 0;
  border-left: 2px solid transparent; padding: 6px 16px; cursor: pointer;
  color: var(--cp-text-muted); font-family: var(--font-sans); font-size: 12.5px;
  line-height: 1.45;
}
.hit:hover, .hit:focus { background: rgba(55, 224, 255, .08); border-left-color: var(--cp-cyan); outline: none; }
.hit .where {
  display: block; font-family: var(--font-mono); font-size: 9.5px;
  letter-spacing: .1em; text-transform: uppercase; color: var(--cp-text-dim);
}
.hit mark { background: rgba(255, 208, 96, .25); color: var(--cp-gold); border-radius: 2px; }
.no-hits { padding: 8px 16px; font-family: var(--font-mono); font-size: 11px; color: var(--cp-text-dim); }

/* --- The guide --- */
.content { margin-left: var(--nav-width); padding: 28px 40px 80px; max-width: 1020px; }
.page { padding-bottom: 28px; border-bottom: 1px dashed var(--cp-line); margin-bottom: 28px; }
.page:last-of-type { border-bottom: 0; }
h1, h2, h3, h4, h5, h6 { font-family: var(--font-mono); line-height: 1.3; scroll-margin-top: 20px; }
h1 {
  margin: 8px 0 18px; font-size: 22px; letter-spacing: .06em; text-transform: uppercase;
  background: linear-gradient(90deg, var(--cp-gold), var(--cp-amber) 45%, var(--cp-red));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
h2 {
  margin: 32px 0 12px; padding-bottom: 6px; font-size: 15px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cp-magenta); border-bottom: 1px solid var(--cp-line);
}
h3 { margin: 24px 0 8px; font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--cp-cyan); }
h4, h5, h6 { margin: 18px 0 6px; font-size: 12px; letter-spacing: .06em; color: var(--cp-green); }
p { margin: 10px 0; color: var(--cp-text-muted); }
strong { color: var(--cp-text); }
em { color: var(--cp-text); }
ul, ol { margin: 10px 0; padding-left: 24px; color: var(--cp-text-muted); }
li { margin: 4px 0; }
li > ul, li > ol { margin: 4px 0; }
hr { border: 0; border-top: 1px solid var(--cp-line); margin: 24px 0; }
code {
  font-family: var(--font-mono); font-size: 12px; color: var(--cp-cyan);
  background: rgba(55, 224, 255, .08); border: 1px solid rgba(55, 224, 255, .18);
  border-radius: 3px; padding: 1px 4px;
}
pre.code {
  font-size: 11.5px; line-height: 1.6; color: var(--cp-text-muted);
  background: rgba(11, 7, 22, .9); border: 1px solid var(--cp-line);
  border-radius: var(--radius); padding: 12px 16px; overflow-x: auto; margin: 14px 0;
}
pre.code code { background: none; border: 0; padding: 0; color: inherit; font-size: inherit; }
blockquote {
  margin: 14px 0; padding: 8px 16px; background: rgba(255, 79, 216, .05);
  border-left: 3px solid var(--cp-magenta); border-radius: 0 var(--radius) var(--radius) 0;
}
blockquote p { margin: 4px 0; color: var(--cp-text-muted); }
table { border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 13px; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--cp-line); padding: 7px 10px; text-align: left; vertical-align: top; }
th {
  background: var(--cp-raised); color: var(--cp-text); font-family: var(--font-mono);
  font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
}
td { color: var(--cp-text-muted); }
tbody tr:nth-child(even) { background: rgba(27, 18, 50, .35); }
img {
  display: block; max-width: 100%; height: auto; margin: 16px 0;
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  box-shadow: 0 8px 24px -16px rgba(255, 79, 216, .35);
}
.no-image { font-family: var(--font-mono); font-size: 11px; color: var(--cp-text-dim); }
/* A link the VM cannot follow says so where it stands. */
.net-note { font-family: var(--font-mono); font-size: 10.5px; color: var(--cp-text-dim); }
.note {
  padding: 10px 14px; background: rgba(255, 176, 0, .07);
  border: 1px solid rgba(255, 176, 0, .3); border-left: 3px solid var(--cp-amber);
  border-radius: var(--radius); color: var(--cp-text-muted);
}
pre.mermaid {
  margin: 18px 0; padding: 14px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  overflow-x: auto; text-align: left; font-family: var(--font-mono); font-size: 11px;
  color: var(--cp-text-dim);
}
/* A diagram fits its box; a click gives it the size Mermaid laid it out at and
   the box scrolls, because a wide flowchart shrunk into one column has labels
   nobody can read. */
pre.mermaid svg { max-width: 100%; height: auto; }
pre.mermaid { cursor: zoom-in; }
pre.mermaid.zoomed { cursor: zoom-out; }
/* Mermaid writes the fitted size into the element's style attribute, so the
   zoomed state has to beat it. */
pre.mermaid.zoomed svg { max-width: none !important; }
.wiki-footer {
  margin-left: var(--nav-width); padding: 14px 40px 28px;
  border-top: 1px solid var(--cp-line); background: var(--cp-bar-bottom);
  font-family: var(--font-mono); font-size: 10.5px; letter-spacing: .06em;
  color: var(--cp-text-dim);
}
.wiki-footer code { background: none; border: 0; color: var(--cp-text-muted); }
.top {
  position: fixed; right: 18px; bottom: 18px; padding: 8px 12px;
  background: var(--cp-card); border: 1px solid var(--cp-line); border-radius: var(--radius);
  color: var(--cp-text-muted); font-family: var(--font-mono); font-size: 10px;
  letter-spacing: .1em; text-transform: uppercase; cursor: pointer;
}
.top:hover { color: var(--cp-magenta); border-color: var(--cp-magenta); }
@media (max-width: 900px) {
  .sidebar { position: static; width: auto; height: auto; }
  .scroller { max-height: 320px; }
  .content, .wiki-footer { margin-left: 0; padding-left: 18px; padding-right: 18px; }
}
"""


def _script(records):
    """The search and the navigation, both in the browser and without a server.

    The hits are built as DOM nodes with textContent, never as HTML: a line of
    the guide is text, in the document as well as in a hit.
    """
    data = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    # No raw "<" in the literal: a line of the guide carrying "</script" would
    # close this element, and one carrying "<!--" on a page that also writes
    # "<script" sends the tokenizer into script-data-double-escaped state, where
    # "</script>" no longer closes anything and the rest of this file - search,
    # navigation, diagram zoom - never runs. "\\u003c" is both valid JSON and a
    # valid JavaScript escape, so the text itself is unchanged.
    data = data.replace("<", "\\u003c")
    return """
const WIKI_INDEX = %s;

(function () {
  const search = document.getElementById('search');
  const results = document.getElementById('results');
  const toc = document.getElementById('toc');
  const links = Array.prototype.slice.call(toc.querySelectorAll('a[data-target]'));
  const items = Array.prototype.slice.call(toc.querySelectorAll('.toc-item'));

  // --- Search: substring over heading, page and text line ---
  function hitNode(rec, needle) {
    const button = document.createElement('button');
    button.className = 'hit';
    button.type = 'button';
    button.dataset.target = rec.h;
    const where = document.createElement('span');
    where.className = 'where';
    where.textContent = rec.pt + (rec.ht && rec.ht !== rec.pt ? '  >  ' + rec.ht : '');
    button.appendChild(where);
    const line = rec.t;
    const at = line.toLowerCase().indexOf(needle);
    if (at < 0) {
      button.appendChild(document.createTextNode(line));
    } else {
      let from = Math.max(0, at - 60);
      if (from > 0) {
        const space = line.indexOf(' ', from);
        from = space >= 0 && space < at ? space + 1 : from;
      }
      const to = Math.min(line.length, at + needle.length + 90);
      button.appendChild(document.createTextNode((from > 0 ? '\\u2026' : '') + line.slice(from, at)));
      const mark = document.createElement('mark');
      mark.textContent = line.slice(at, at + needle.length);
      button.appendChild(mark);
      button.appendChild(document.createTextNode(
        line.slice(at + needle.length, to) + (to < line.length ? '\\u2026' : '')));
    }
    return button;
  }

  function run() {
    const needle = search.value.trim().toLowerCase();
    results.textContent = '';
    if (needle.length < 2) {
      results.classList.remove('open');
      return;
    }
    const hits = [];
    for (let i = 0; i < WIKI_INDEX.length && hits.length < 80; i++) {
      const rec = WIKI_INDEX[i];
      if (rec.t.toLowerCase().indexOf(needle) >= 0 ||
          rec.ht.toLowerCase().indexOf(needle) >= 0 ||
          rec.pt.toLowerCase().indexOf(needle) >= 0) {
        hits.push(rec);
      }
    }
    const count = document.createElement('p');
    count.className = 'no-hits';
    count.textContent = hits.length ? hits.length + (hits.length === 80 ? '+ hits' : ' hits') : 'no hit';
    results.appendChild(count);
    hits.forEach(function (rec) { results.appendChild(hitNode(rec, needle)); });
    results.classList.add('open');
  }

  search.addEventListener('input', run);
  search.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { search.value = ''; run(); search.blur(); }
  });
  results.addEventListener('click', function (event) {
    const button = event.target.closest('button.hit');
    if (button) { jump(button.dataset.target); }
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === '/' && event.target !== search) { event.preventDefault(); search.focus(); }
  });

  function jump(id) {
    const target = document.getElementById(id);
    if (!target) { return; }
    target.scrollIntoView({ block: 'start' });
    history.replaceState(null, '', '#' + id);
    mark(id);
  }

  // --- The place in the navigation ---
  function mark(id) {
    links.forEach(function (link) { link.classList.toggle('active', link.dataset.target === id); });
    const active = toc.querySelector('a.active');
    const page = active ? active.closest('.toc-item') : null;
    items.forEach(function (item) { item.classList.toggle('collapsed', !!page && item !== page); });
  }

  const marks = Array.prototype.slice.call(
    document.querySelectorAll('.content h1[id], .content h2[id]'));
  function spy() {
    let current = marks.length ? marks[0].id : null;
    for (let i = 0; i < marks.length; i++) {
      if (marks[i].getBoundingClientRect().top <= 120) { current = marks[i].id; } else { break; }
    }
    if (current) { mark(current); }
  }
  window.addEventListener('scroll', function () { window.requestAnimationFrame(spy); }, { passive: true });
  toc.addEventListener('click', function (event) {
    const link = event.target.closest('a[data-target]');
    if (link) { mark(link.dataset.target); }
  });
  document.querySelector('.top').addEventListener('click', function () {
    window.scrollTo({ top: 0 });
  });

  // --- A diagram at full size: a wide one is unreadable fitted into a column ---
  const FIT = 'Click to see the diagram at full size';
  const FULL = 'Click to fit the diagram into the page';
  Array.prototype.forEach.call(document.querySelectorAll('pre.mermaid'), function (pre) {
    pre.title = FIT;
    pre.addEventListener('click', function () {
      const svg = pre.querySelector('svg');
      if (!svg) { return; }
      const zoom = !pre.classList.contains('zoomed');
      pre.classList.toggle('zoomed', zoom);
      const box = svg.viewBox && svg.viewBox.baseVal;
      svg.style.width = zoom && box && box.width ? Math.round(box.width) + 'px' : '';
      pre.title = zoom ? FULL : FIT;
    });
  });
  if (location.hash.length > 1) { mark(location.hash.slice(1)); } else { spy(); }
})();
""" % data


def _document(pages, bundle, records, built_at, commit):
    out = ['<!DOCTYPE html>', '<html lang="en" data-theme="cyberpunk">', '<head>',
           '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>%s &mdash; Wiki</title>' % TITLE,
           '<style>%s</style>' % _style(), '</head>', '<body>',
           '<aside class="sidebar">',
           '<div class="brand"><b>%s</b><span>%s</span></div>' % (TITLE, SUBTITLE),
           '<div class="search-box">',
           '<input id="search" type="search" placeholder="Search the guide"'
           ' autocomplete="off" spellcheck="false" aria-label="Search the guide">',
           '<p class="search-hint">all pages, in this file &middot; / to focus</p>',
           '</div>',
           '<div class="scroller"><div id="results"></div>',
           _nav(pages), '</div></aside>',
           '<main class="content">']
    for page in pages:
        # A page whose first heading is not an <h1> has no element carrying its
        # id, and its navigation entry and search hits would jump nowhere: the
        # section is the fallback anchor then (never both, or the id is twice in
        # the document).
        has_anchor = any(hid == page["id"] for _, hid, _ in page["headings"])
        out.append('<section class="page"%s data-page="%s">'
                   % ("" if has_anchor else ' id="%s"' % page["id"], page["id"]))
        out.append(page["html"])
        if page["name"] == "README.md":
            out.append(_demo_note())
        out.append("</section>")
    out.append("</main>")
    out.append(_footer(built_at, commit))
    out.append('<button class="top" type="button">Top</button>')
    out.append(MERMAID_SCRIPT_OPEN + bundle + "</script>")
    out.append("<script>mermaid.initialize({startOnLoad:true,securityLevel:'strict',"
               "theme:'dark',fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',"
               "flowchart:{useMaxWidth:true},state:{useMaxWidth:true},"
               "sequence:{useMaxWidth:true},"
               "themeVariables:{darkMode:true,background:'#140d24',primaryColor:'#1b1232',"
               "primaryBorderColor:'#ff4fd8',primaryTextColor:'#f3eefc',lineColor:'#37e0ff',"
               "secondaryColor:'#251a3d',tertiaryColor:'#120a22',textColor:'#c9bfe3',"
               "clusterBkg:'#120a22',clusterBorder:'#251a3d'}});</script>")
    out.append("<script>%s</script>" % _script(records))
    out.append("</body></html>")
    return "\n".join(out)


def build_wiki(docs_dir, static_dir, mermaid_path, out_path):
    """Build the one-file wiki and return its HTML.

    Reads the pages in the order of docs/README.md, embeds every PNG of
    static/ as a `data:` URI and the pinned Mermaid bundle, and writes
    out_path. Raises WikiError - and writes nothing - when the Mermaid copy is
    missing or has changed, or when the index is not there.
    """
    index_path = os.path.join(docs_dir, "README.md")
    if not os.path.isfile(index_path):
        raise WikiError("no index to read the page order from: %s/README.md" % docs_dir)
    bundle = read_mermaid(mermaid_path)
    images = embed_images(static_dir)
    with open(index_path, encoding="utf-8") as fh:
        order = page_order(fh.read())
    pages = []
    records = []
    for name in order:
        path = os.path.join(docs_dir, name)
        if not os.path.isfile(path):
            raise WikiError("docs/README.md links %s, which does not exist" % name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        html = render_markdown(text, images, page=name)
        found = headings(html)
        title = found[0][2] if found and found[0][0] == 1 else page_id(name)
        pages.append({"name": name, "id": page_id(name), "title": title,
                      "html": html, "headings": found})
        records.extend(search_records(name, title, text))
    built_at = datetime.datetime.utcnow().replace(microsecond=0)
    document = _document(pages, bundle, records, built_at, short_commit())
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    # Beside the target, then renamed: 15 MB can run into a full disk, and a
    # truncated wiki.html is reported as present by /api/wiki and linked by the
    # help - on the VM it would be the only documentation there is. os.replace
    # is atomic within one file system, and the temporary file goes with a write
    # that failed instead of staying behind as rubbish.
    temporary = out_path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as fh:
            fh.write(document)
        os.replace(temporary, out_path)
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build the offline wiki (one HTML file) from docs/.")
    parser.add_argument("--docs", default=os.path.join(ROOT, "docs"))
    parser.add_argument("--static", default=os.path.join(ROOT, "static"))
    parser.add_argument("--mermaid", default=os.path.join(ROOT, "scripts", "wiki", "mermaid.min.js"))
    parser.add_argument("-o", "--out", default=os.path.join(ROOT, "webui", "static", "wiki.html"))
    args = parser.parse_args(argv)
    try:
        document = build_wiki(args.docs, args.static, args.mermaid, args.out)
    except WikiError as err:
        sys.stderr.write("[docs] %s\n" % err)
        return 1
    pages = document.count('<section class="page"')
    size = os.path.getsize(args.out)
    sys.stdout.write("[docs] %s: %d pages, %.1f MB\n"
                     % (os.path.relpath(args.out, ROOT), pages, size / (1024.0 * 1024.0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
