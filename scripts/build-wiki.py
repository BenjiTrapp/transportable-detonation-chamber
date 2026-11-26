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

The same text is also published as a website, one address per page (see the
section "The website" at the end of this file): the renderer takes a link
strategy and unscoped anchors for it, everything else it shares with the wiki.
    page_url(name)                          the folder a page is read under
    site_link_target(url, page)             where a link of the website points
    file_images(static_dir)                 the screenshots as shipped files
    search_index(pages)                     the search index the browser fetches
    readme_html(text, images, logo)         the README as the site's front page
    site_page(page, pages, built_at, commit)        one page of the website
    build_site(docs_dir, static_dir, mermaid_path, out_dir, readme_path,
               logo_path, wiki_path)

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
    """What a render needs besides the lines: the pictures, the page, and the
    two things the two outputs disagree about.

    `links` is the link strategy: left out, a link points inside this one file
    (the wiki); the website passes site_link_target, where another page is
    another file. `scoped` names the anchors: the wiki needs "rizin--limits",
    because every page stands in the same document and a bare "limits" would be
    in it four times; a page of the website is a file of its own, so its
    anchors are the heading's own slug - the one the docs write by hand.
    """

    def __init__(self, images, page, links=None, scoped=True, net_note=True,
                 reserved=None):
        self.images = images or {}
        self.page = page
        self.links = links or _link_target
        self.scoped = scoped
        # "needs network access" belongs to the reader who cannot follow the
        # link, which is the one the wiki was built for. The website stands in
        # the network itself and asks for net_note=False - it is its own
        # choice, so an output that brings its own links and is still read
        # offline can keep the note.
        self.net_note = net_note
        # The counter lives here, not in heading_id(): it is the state of one
        # render of one page, so two headings with the same words get two ids
        # ("limits", "limits-2") while rendering the same page again gives the
        # same ids. A module-level counter would hand out a different id on
        # every build - the website's search would then aim at anchors that
        # moved, and the wiki's navigation at ones that are not there.
        self.used_ids = {}
        # Every id handed out, not only the bases: "Limits 2" slugs to
        # "limits-2" on its own, which is what the second "## Limits" was
        # given, and two elements with one id send a link or a search hit to
        # whichever of them comes first.
        #
        # `reserved` seeds it with the ids the page already carries before the
        # prose begins. The website's shell writes id="content", "search",
        # "register" and the rest *above* the prose, so a page with "## Search"
        # would otherwise get id="search" a second time and the register's own
        # jump to that section would scroll to the search box. The wiki passes
        # nothing: its anchors carry their page ("rizin--search"), so they
        # cannot meet the document's own ids.
        self.anchors = set(reserved or ())

    def heading_id(self, text, level=2):
        if self.scoped:
            base = page_id(self.page) if (level == 1 and self.page) else heading_id(self.page, text)
        else:
            # A heading of symbols alone (an emoji, a dash) slugs to nothing,
            # and an empty id is a link and a search hit aiming at nowhere.
            base = slug(text) or page_url(self.page) or "section"
        seen = self.used_ids.get(base, 0)
        anchor = base if not seen else "%s-%d" % (base, seen + 1)
        while anchor in self.anchors:  # the count is not proof that it is free
            seen += 1
            anchor = "%s-%d" % (base, seen + 1)
        self.used_ids[base] = seen + 1
        self.anchors.add(anchor)
        return anchor


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
        target = ctx.links(html_lib.unescape(m.group(2)), ctx.page)
        if target is None:
            return "%s (%s)" % (m.group(1), m.group(2))  # refused, kept visible
        external = target.startswith("http")
        extra = ' target="_blank" rel="noopener"' if external else ""
        # A path out of docs/ became a URL on github.com: on the VM that is a
        # dead end, and the reader has to be told before the click, not after.
        note = ('<span class="net-note"> (%s)</span>' % NETWORK_NOTE
                if ctx.net_note and target.startswith(REPO_BLOB) else "")
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


def _interrupts_paragraph(line):
    """Whether this list line may start a list right under a paragraph line.

    CommonMark: an ordered list interrupts a paragraph only when it starts at
    1. Without that rule a wrapped sentence whose next line begins "3008) with
    their switches" is read as a list marker - the paragraph is cut in three
    and the token "3008)" is swallowed by the marker. A list standing on its
    own may still begin at any number; this is only about interrupting.
    """
    found = _LIST.match(line)
    if not found or _indent(line) != 0:
        return False
    marker = found.group(2)
    return marker[:-1] == "1" if marker[0].isdigit() else True


def _starts_block(line):
    """Whether a line ends the paragraph above it."""
    if not line.strip():
        return True
    if _HEADING.match(line) or _FENCE.match(line) or _RULE.match(line):
        return True
    if line.lstrip().startswith(">"):
        return True
    if _interrupts_paragraph(line):
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


def render_markdown(text, images, page="", links=None, scoped=True, net_note=True,
                    reserved=None):
    """One page of markdown as HTML. Pure: `images` maps file names to sources.

    Carries headings, paragraphs, lists (nested too), fenced code blocks with a
    language, inline code, bold, italic, links, images, tables, blockquotes,
    horizontal rules and ```mermaid blocks. A line it does not know stays
    readable as text instead of being swallowed, and nothing in the source can
    become live HTML.

    The defaults are the offline wiki: links point inside the one file, anchors
    carry their page ("rizin--limits"), a link into the repository says it
    needs a network, and `images` holds `data:` URIs. The website passes
    `links=site_link_target, scoped=False, net_note=False` instead, so a link
    to another page is "../web-ui/", an anchor is the heading's own slug, and
    `images` (from file_images) holds the paths of the shipped files; with
    `reserved=SITE_SHELL_IDS` no heading can take an id the page shell owns.
    """
    lines = text.replace("\r\n", "\n").replace("\t", "    ").split("\n")
    return _blocks(lines, _Ctx(images, page, links=links, scoped=scoped,
                               net_note=net_note, reserved=reserved))


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


def _mermaid_init():
    """The Mermaid settings both outputs use: the product's palette, dark.

    `useMaxWidth` lets a diagram fit the column it stands in; a click gives it
    the size it was laid out at (see the zoom in the page's script).
    """
    return ("mermaid.initialize({startOnLoad:true,securityLevel:'strict',"
            "theme:'dark',fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',"
            "flowchart:{useMaxWidth:true},state:{useMaxWidth:true},"
            "sequence:{useMaxWidth:true},"
            "themeVariables:{darkMode:true,background:'#140d24',primaryColor:'#1b1232',"
            "primaryBorderColor:'#ff4fd8',primaryTextColor:'#f3eefc',lineColor:'#37e0ff',"
            "secondaryColor:'#251a3d',tertiaryColor:'#120a22',textColor:'#c9bfe3',"
            "clusterBkg:'#120a22',clusterBorder:'#251a3d'}});")


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
    out.append("<script>%s</script>" % _mermaid_init())
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
    # UTC, and not utcnow(): that one is deprecated in 3.12 (the version the
    # publishing workflow pins) and scheduled for removal. tzinfo is dropped
    # again so the footer's strftime stays what it was, to the byte.
    built_at = datetime.datetime.now(datetime.timezone.utc).replace(
        tzinfo=None, microsecond=0)
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


# --- The website -------------------------------------------------------------
#
# The second output of the same text: instead of one file for a machine with no
# network, one address per page on GitHub Pages. Only three things change for
# the renderer, and all three are here - where a link goes, what an anchor is
# called (render_markdown's `scoped=False`) and where a picture comes from.


# The shipped extras, relative to the root of the site. Every link on the site
# is relative ("../rizin/"): the pages live under a project's sub-path on
# GitHub Pages and have to open from a local folder just the same, where a path
# starting with "/" would leave the site altogether.
SITE_ASSETS = "assets"
SITE_IMG = SITE_ASSETS + "/img"

# The front page is the repository's README, so it has no folder of its own:
# from a page of the guide it is one level up.
SITE_HOME = "../"

# The shipped extras, by their place under the site's root.
SITE_STYLE = SITE_ASSETS + "/style.css"
SITE_SCRIPT = SITE_ASSETS + "/site.js"
SITE_MERMAID = SITE_ASSETS + "/mermaid.min.js"
SITE_LOGO = SITE_ASSETS + "/tdc-logo.png"
SITE_DEMO = SITE_ASSETS + "/demo.gif"
SITE_WIKI = "wiki.html"
# The search index, fetched when a reader first types. A file, not data in the
# page: the wiki carries its index in the document because it is read from
# file:// with no server behind it, while the website is served - so every
# page shares one copy instead of carrying the same 200 KB each.
SITE_SEARCH = "search.json"

# The ids the page shell writes around the prose, before the prose begins. A
# heading of a docs page is numbered against these too (render_markdown's
# `reserved`): the shell's elements come first in the document, so a page with
# "## Search" would otherwise carry id="search" twice and the register's jump
# to that section, and every search hit in it, would land on the search box.
# Prefixing them instead would mean touching the style sheet and the script,
# where "#content" is also the skip link's target.
SITE_SHELL_IDS = ("content", "register", "search", "results", "search-count",
                  "search-hits")

# A short name for a page whose own h1 is too long for a list entry and for
# "Previous: ...". The guide's index is called "Transportable Detonation
# Chamber - Documentation", which wraps to two lines in the register and reads
# oddly in the pager; the page keeps that h1, its <title> and its entry in the
# search index - only the two places where it is referred to in passing use the
# short name.
SITE_SHORT_TITLES = {"README.md": "Overview"}


def site_label(page):
    """How a page is named where another page points at it."""
    return SITE_SHORT_TITLES.get(page["name"], page["title"])

# What this build wrote, kept in the folder it wrote it to. The next build
# sweeps exactly the paths on that list and nothing else, so a file somebody
# else put there - a CNAME, a folder of notes, a checkout - is never deleted by
# us; and a folder that has things in it but no list of ours is refused rather
# than mixed into.
SITE_MANIFEST = ".site-files"

# The icon of a tab, as a few bytes of SVG in the page itself: the logo is
# 117 KB and would be fetched again for every address of the site. The
# namespace in it is a name, not an address - nothing is requested.
SITE_ICON = (
    "data:image/svg+xml,"
    "%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2032%2032'%3E"
    "%3Crect%20width='32'%20height='32'%20rx='7'%20fill='%230b0716'/%3E"
    "%3Cpath%20d='M16%204%20L27%2028%20L5%2028%20Z'%20fill='%23ff4fd8'/%3E"
    "%3Ccircle%20cx='16'%20cy='21'%20r='3.5'%20fill='%23ffd060'/%3E%3C/svg%3E")

# What the header says under the product's name, on every page.
SITE_SUBTITLE = "Documentation"


def page_url(name):
    """The folder a page of the website lives in: "web-ui.md" -> "web-ui".

    The guide's index is the whole guide's front page and is read under
    /guide/, not /readme/ - it is the address the README and the navigation
    send a reader to.
    """
    folder = page_id(name)
    return "guide" if folder == "readme" else folder


def _site_anchor(anchor):
    """A link's anchor as the website writes it: "#charts", or "" for none.

    The docs write GitHub's own anchors by hand (`](#own-dashboards)`), which
    is what a page of the website carries, so this is the same slug the
    headings get - and it stays right if a doc ever writes `#Own Dashboards`.
    """
    anchor = slug(anchor or "")
    return "#" + anchor if anchor else ""


# --- The search index of the website -----------------------------------------
#
# `search_records` is the wiki's: it names its anchors the wiki's way
# ("rizin--limits"), because every page of the wiki stands in one document. A
# page of the website is a file of its own and carries the heading's own slug,
# numbered by the renderer when two headings have the same words ("limits",
# "limits-2"). So the anchors are not slugged again here - they are taken from
# the page that was written, which is the only place that knows which of the
# two a line stands under.


def _site_heading(found, start, text):
    """The id of the next heading of the page whose words are `text`.

    Returns (id, cursor): the id as the rendered page carries it, and where to
    go on looking. Compared by slug, not by the words themselves, so a heading
    written with code marks matches the plain words the index reports, and an
    entity (`&amp;`) matches the character.

    The search walks forward only, in document order, so the n-th section with
    those words gets the n-th id with them ("limits", "limits-2") - which is
    the whole point: the words alone cannot tell two sections apart. A heading
    the walk does not know - the front page's card names, a `#` inside a block
    quote - is stepped over rather than mistaken for the one that is wanted.
    """
    want = slug(text)
    for i in range(start, len(found)):
        if slug(found[i][2]) == want:
            return found[i][1], i + 1
    return None, start


def _site_sections(text):
    """The page's markdown cut at its heading lines: (heading or None, lines).

    In document order, so the n-th section of the walk is the n-th heading of
    the page. This is what tells two sections with the same words apart - the
    records of a section carry its words and nothing that says which of the
    two it is, so the lines of the second "## Limits" would otherwise be filed
    under the first one's id.

    The fence rules are `search_records`' own, and have to stay its own: a
    `##` inside a fenced block is a comment and no section (the guide's blocks
    are full of them), and a ```` block holding a ``` line stays one block.
    """
    sections = [(None, [])]
    fence = None
    ticks = 0
    for line in text.replace("\r\n", "\n").split("\n"):
        fenced = _FENCE.match(line)
        if fenced:
            if fence is None:
                fence, ticks = fenced.group(3).lower(), len(fenced.group(2))
            elif len(fenced.group(2)) >= ticks and not fenced.group(3):
                fence, ticks = None, 0
            sections[-1][1].append(line)
            continue
        head = _HEADING.match(line) if fence is None else None
        if head:
            sections.append((re.sub(r"[`*]", "", head.group(2)).strip(), [line]))
            continue
        sections[-1][1].append(line)
    # The lines above the first heading are a section of their own, and on
    # every page of the guide there are none (the file starts with its h1).
    return [(name, "\n".join(lines)) for name, lines in sections
            if name is not None or "\n".join(lines).strip()]


def site_records(page):
    """(anchor, heading, line) of every line of one page, with the site's ids.

    `page` is a page dict of build_site: its markdown in "text" and the
    headings of the written file in "headings". The markdown is cut into its
    sections first and the wiki's `search_records` is asked for one section at
    a time, so each line's section is the loop's own count rather than
    something inferred from the records - and every anchor handed back is an
    id read off that page, a target the reader really lands on.
    """
    found = page["headings"]
    top = found[0][1] if found else ""
    records = []
    at = 0
    for heading, body in _site_sections(page["text"]):
        if heading is None:
            anchor = top
        else:
            anchor, at = _site_heading(found, at, heading)
        if anchor is None:
            raise WikiError(
                "docs/%s has a section the written page carries no id for: %s"
                " (#%s)\n"
                "  every hit of the search jumps to an id of the page it names,"
                " so a\n"
                "  section with no id of its own would drop the reader somewhere"
                " else\n"
                "  on that page and nothing would say so.\n"
                "  the index and the page come out of one render, so this means"
                " the\n"
                "  renderer's heading ids and the index's heading lines have"
                " drifted\n"
                "  apart: make them agree again."
                % (page["name"], heading, slug(heading)))
        for record in search_records(page["name"], page["title"], body):
            records.append((anchor, record["ht"], record["t"]))
    return records


def search_index(pages):
    """The website's search index: the pages, and every line with its heading.

    `{"pages": [{"url", "title"}], "records": [[page, anchor, heading, line]]}`
    - the page as its position in that list, so every page name and
    titles are written once instead of once per line. The browser fetches this
    when a reader first types (see the search in assets/site.js).
    """
    index = {"pages": [], "records": []}
    for i, page in enumerate(pages):
        index["pages"].append({"url": page["url"], "title": page["title"]})
        for anchor, heading, line in site_records(page):
            index["records"].append([i, anchor, heading, line])
    return index


def site_link_target(url, page):
    """Where a link of the guide points on the website.

    The pages are separate files, so another page of the guide is the folder
    next to this one (`../web-ui/`) and an anchor of this page needs no page in
    its name. `../README.md` is the site's front page, a screenshot is the copy
    under assets/, and every other file of the repository - including a
    relative path the site does not publish, such as docs/superpowers/ - is
    read on github.com. A scheme that could run code is refused, as in the
    wiki, and so is a path from the server's root, which no relative site can
    keep.
    """
    if url.startswith("./"):
        url = url[2:]  # "./rizin.md" is the page rizin.md
    page_link = re.match(r"^([A-Za-z0-9_-]+)\.md(?:#(.*))?$", url, re.I)
    if page_link:
        return "../%s/%s" % (page_url(page_link.group(1) + ".md"),
                             _site_anchor(page_link.group(2)))
    if url.startswith("#"):
        return _site_anchor(url[1:]) or "#"
    out_of_docs = re.match(r"^\.\./([^#]*)(?:#(.*))?$", url)
    if out_of_docs:
        path, fragment = out_of_docs.group(1), out_of_docs.group(2)
        if path == "README.md":
            # Our own front page: its anchors are the ones this generator
            # writes, so the fragment is slugged like a heading.
            return SITE_HOME + _site_anchor(fragment)
        picture = re.match(r"^static/([^/]+\.png)$", path, re.I)
        if picture:
            return "../%s/%s" % (SITE_IMG, picture.group(1))
        # A file read on github.com keeps its fragment as it stands: "#L10" is
        # a line of that file, not a heading to slug.
        return REPO_BLOB + path + ("#" + fragment if fragment else "")
    if url.startswith("/"):
        return None  # would leave the site's sub-path, and a local folder too
    if _SAFE_SCHEME.match(url):
        return url
    if ":" in url.split("/")[0]:
        return None  # javascript:, vbscript:, data:text/html, ...
    # Anything else relative is a file of the repository under docs/ that the
    # site does not publish: handing the path on as it stands would leave a
    # link that resolves to nothing.
    return REPO_BLOB + "docs/" + url


def file_images(static_dir):
    """Every PNG of static/ by file name, as the path a page of the site uses.

    The same shape embed_images has, so the renderer needs no second branch for
    a picture. No `data:` URI here: the pictures are shipped as files under
    assets/img/, where a browser with a network loads each one when the reader
    reaches it, instead of carrying 12 MB of Base64 into every page.
    """
    images = {}
    if not os.path.isdir(static_dir):
        return images
    for name in sorted(os.listdir(static_dir)):
        # A directory named like a picture is not one: every name here is a
        # file the build copies into assets/img/.
        if name.lower().endswith(".png") and os.path.isfile(os.path.join(static_dir, name)):
            images[name] = "../%s/%s" % (SITE_IMG, name)
    return images


def home_images(static_dir):
    """The same pictures as file_images, as the front page has to write them.

    The front page is the root of the site, so the copies are one folder down
    ("assets/img/x.png") and not one up.
    """
    cut = len(SITE_HOME)
    return dict((name, src[cut:]) for name, src in file_images(static_dir).items())


def home_link_target(url, page):
    """Where a link of the front page points.

    The front page is the repository's README, rendered into the root of the
    site, so it writes its links from the root of the repository: `docs/x.md`
    is the page /x/, `static/x.png` and `tdc-logo.png` are shipped copies, and
    nothing may start with "../" - from the root that would leave the published
    site. Everything else is the strategy of a page of the guide (see
    site_link_target): the web as it stands, a file of the repository on
    github.com, a scheme that could run code refused.
    """
    if url.startswith("./"):
        url = url[2:]
    page_link = re.match(r"^docs/([A-Za-z0-9_-]+)\.md(?:#(.*))?$", url, re.I)
    if page_link:
        return "%s/%s" % (page_url(page_link.group(1) + ".md"),
                          _site_anchor(page_link.group(2)))
    if url.startswith("#"):
        return _site_anchor(url[1:]) or "#"
    if url.startswith("/"):
        return None  # would leave the site's sub-path, and a local folder too
    if _SAFE_SCHEME.match(url):
        return url
    if ":" in url.split("/")[0]:
        return None  # javascript:, vbscript:, data:text/html, ...
    path, _, fragment = url.partition("#")
    picture = re.match(r"^static/([^/]+\.png)$", path, re.I)
    if picture:
        return "%s/%s" % (SITE_IMG, picture.group(1))
    if path.lower() == DEMO_GIF:
        return SITE_DEMO  # the demo video is shipped: in the web that is fine
    if path.lower() == os.path.basename(SITE_LOGO):
        return SITE_LOGO
    # Any other file of the repository is read on github.com, fragment as it
    # stands ("#L10" is a line of that file, not a heading to slug).
    return REPO_BLOB + path + ("#" + fragment if fragment else "")


# --- The front page ----------------------------------------------------------
#
# The front page is the repository's README, whole and in its order: no
# section is picked, reordered or left out, so Credits and License stand on
# the one public page they belong on, the README's own jump targets stay
# alive, and no second text assembler can drift behind the README. Three
# things about that file are not markdown, and the three helpers below are
# what happens to them.

# The page the front page's links are written from: the repository's root.
HOME_PAGE = "README.md"

# The section whose feature blocks become cards. The README names it itself -
# one of its own badges links at #what-it-does - and what is recognised inside
# it is the pattern of a feature, not a list of the ten there are today.
HOME_FEATURES = "what-it-does"

# The two raw HTML forms of the README this output understands: a centred
# block that is a picture, and one that is a line of text. Everything else -
# another tag, another attribute, another alignment, a mark that is not closed
# - stays the text the parser makes of it, as raw HTML does on every other
# page. One `onerror=` through here would be live code on a published page.
_HOME_CENTRED = re.compile(r'^\s*<(p|h1)\s+align="center"\s*>', re.I)
_HOME_MARKS = ("strong", "b", "em", "i", "sub", "sup", "code")
_HOME_TOKEN = re.compile(
    r'<br\s*/?>'
    r'|<(/?)(' + "|".join(_HOME_MARKS) + r')\s*>'
    r'|<a\s+href="([^"<>]*)"\s*>'
    r'|</a\s*>'
    r'|<img\s+([^<>]*?)\s*/?>', re.I)
# What an <img> of such a block may carry. Anything else is not a picture.
_HOME_IMG_ATTRS = ("src", "alt", "width", "height", "title")
_HOME_ATTR = re.compile(r'\s*([A-Za-z-]+)\s*=\s*"([^"]*)"\s*')


def _home_text(raw):
    """A run of text inside a centred block, as the page may show it.

    The entities the README writes (`&mdash;`, `&bull;`) are read and the
    result escaped again, so a `&lt;script&gt;` in the source comes out as the
    text it is and not as a tag.
    """
    return esc(html_lib.unescape(re.sub(r"\s+", " ", raw)))


def _home_attrs(raw):
    """The attributes of an <img> of a centred block, or None for a stray one.

    Only the ones a picture needs, every one quoted, and nothing left over: an
    `onerror=`, an unquoted value or a second tag inside the attributes makes
    the whole block fall back to text.
    """
    attrs = {}
    for m in _HOME_ATTR.finditer(raw):
        name = m.group(1).lower()
        if name not in _HOME_IMG_ATTRS:
            return None
        attrs[name] = m.group(2)
    if not attrs.get("src") or _HOME_ATTR.sub("", raw).strip():
        return None
    return attrs


def _home_tokens(inner):
    """The content of a centred block as tokens, or None when it is not one.

    None means "not a form this output understands", and the block stays the
    text the parser makes of it. Everything is checked here: a tag that is not
    in the small list above, an attribute that is not, a mark that is crossed
    or never closed, a stray `<` or `>`.
    """
    tokens = []
    marks = []
    in_link = False
    pos = 0
    for m in _HOME_TOKEN.finditer(inner):
        text = inner[pos:m.start()]
        if "<" in text or ">" in text:
            return None
        if text:
            tokens.append(("text", text))
        pos = m.end()
        whole = m.group(0).lower()
        if whole.startswith("<br"):
            tokens.append(("br", ""))
        elif m.group(2):
            name = m.group(2).lower()
            if m.group(1):
                if not marks or marks[-1] != name:
                    return None  # crossed, or never opened
                marks.pop()
                tokens.append(("close", name))
            else:
                marks.append(name)
                tokens.append(("open", name))
        elif whole.startswith("<a"):
            if in_link:
                return None  # a link inside a link
            in_link = True
            tokens.append(("link", m.group(3)))
        elif whole.startswith("</a"):
            if not in_link:
                return None
            in_link = False
            tokens.append(("unlink", ""))
        else:
            attrs = _home_attrs(m.group(4))
            if attrs is None:
                return None
            tokens.append(("img", attrs))
    rest = inner[pos:]
    if "<" in rest or ">" in rest:
        return None
    if rest:
        tokens.append(("text", rest))
    if marks or in_link:
        return None  # what is opened in the block is closed in it
    return tokens


def _home_badge(attrs):
    """Whether this <img> is a badge: a picture from somewhere else on the web.

    The README's badges are images of img.shields.io - a third-party request
    every time the page opens, which the site does not make. Their labels and
    the links they sit in are the information; the pictures are not.
    """
    return bool(re.match(r"^(?:https?:)?//", attrs.get("src", ""), re.I))


def _home_image(attrs, ctx, logo):
    """One <img> of a centred block as a part, or None for the block to drop.

    A badge becomes its label, a shipped picture its file. `tdc-logo.png` is
    the one picture of the README that does not lie in static/, so the front
    page is told where its copy went.
    """
    alt = _home_text(attrs.get("alt", ""))
    if _home_badge(attrs):
        if not alt.strip():
            return None  # a badge with nothing to say is not a form of ours
        return ("badge", '<span class="chip">%s</span>' % alt.strip())
    name = os.path.basename(attrs["src"].split("#")[0].split("?")[0])
    source = logo if name == os.path.basename(logo) else ctx.images.get(name)
    if not source:
        # Not shipped: name the picture, as the renderer does for a markdown
        # one, instead of a frame that stays empty.
        return ("text", '<span class="no-image">[%s: %s]</span>' % (esc(name), alt))
    return ("picture",
            '<img src="%s" alt="%s" loading="lazy">' % (esc(source), alt))


def _home_chip(tokens, i):
    """(the label, the index after it) when a badge in a link follows, else None."""
    while i < len(tokens) and tokens[i][0] == "text" and not tokens[i][1].strip():
        i += 1
    if i >= len(tokens) or tokens[i][0] != "img" or not _home_badge(tokens[i][1]):
        return None
    label = _home_text(tokens[i][1].get("alt", "")).strip()
    i += 1
    while i < len(tokens) and tokens[i][0] == "text" and not tokens[i][1].strip():
        i += 1
    if not label or i >= len(tokens) or tokens[i][0] != "unlink":
        return None
    return (label, i + 1)


def _home_centred(tag, inner, ctx, logo):
    """One centred block as (what it is, its HTML), or None when it is neither.

    What it is: "title" for the centred `<h1>`, "picture" for a block whose
    content is one shipped picture (with the `<br><sub>` caption the README
    writes under its screenshots), "badges" for a row of badges and nothing
    else, "line" for a centred line of text. The caller uses that to build the
    hero and the cards; nothing of it selects or reorders anything.
    """
    tokens = _home_tokens(inner)
    if tokens is None:
        return None
    parts = []
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        i += 1
        if kind == "text":
            text = _home_text(value)
            parts.append(("text" if text.strip() else "space", text))
        elif kind == "br":
            parts.append(("br", "<br>"))
        elif kind in ("open", "close"):
            parts.append(("mark", "<%s%s>" % ("/" if kind == "close" else "", value)))
        elif kind == "img":
            part = _home_image(value, ctx, logo)
            if part is None:
                return None
            parts.append(part)
        elif kind == "link":
            target = ctx.links(value, ctx.page)
            if target is None:
                return None  # a link that could run code: the block stays text
            chip = _home_chip(tokens, i)
            if chip is not None:
                # A badge in a link is one labelled chip: the picture is
                # dropped, the link it carried is the button.
                parts.append(("badge", '<a class="chip" href="%s">%s</a>'
                                       % (esc(target), chip[0])))
                i = chip[1]
                continue
            extra = ' target="_blank" rel="noopener"' if target.startswith("http") else ""
            parts.append(("link", '<a href="%s"%s>' % (esc(target), extra)))
        else:
            parts.append(("link", "</a>"))
    kinds = [what for what, _ in parts]
    body = "".join(html for _, html in parts).strip()
    if tag == "h1":
        plain = html_lib.unescape(re.sub(r"<[^>]+>", "", body)).strip()
        # A title that is only a picture (or a symbol) slugs to nothing, and
        # the context's fallback is the page's folder - "guide" here, which is
        # the address of the guide's index. The front page's own title is the
        # product's name.
        if not slug(plain):
            plain = TITLE
        # The class goes on the hero around it, not here: headings() reports
        # every heading that carries an id, and it reads `<hN id="...">`.
        return ("title", '<h1 id="%s">%s</h1>' % (ctx.heading_id(plain, 1), body))
    pictures = [at for at, what in enumerate(kinds) if what == "picture"]
    said = [at for at, what in enumerate(kinds) if what != "space"]
    if len(pictures) == 1 and said and said[0] == pictures[0] and "badge" not in kinds:
        return ("picture", _home_figure(parts, pictures[0]))
    if "badge" in kinds and not [what for what in kinds
                                 if what in ("text", "picture", "link")]:
        return ("badges", '<p class="badges">%s</p>' % body)
    return ("line", '<p class="centred">%s</p>' % body)


def _home_figure(parts, at):
    """A centred picture with what the README writes under it as its caption."""
    caption = "".join(html for _, html in parts[at + 1:]).strip()
    caption = re.sub(r"^(?:<br>|\s)+", "", caption)
    only = re.match(r"^<sub>(.*)</sub>$", caption, re.S)
    if only:  # the README's captions are one <sub>; the sheet sizes them
        caption = only.group(1)
    if caption:
        return ('<figure class="shot">%s<figcaption>%s</figcaption></figure>'
                % (parts[at][1], caption))
    return '<figure class="shot">%s</figure>' % parts[at][1]


def _home_chunks(lines, ctx, logo):
    """The README as (what it is, payload): ("md", lines) and centred blocks.

    A centred block whose form this output does not understand is not taken
    out: its lines stay in the markdown run, where the parser escapes them to
    text the way it does everywhere else. Neither is one inside a fenced code
    block - there it is an example of the markup, and the fence around it is
    the one place that shows every line as it stands.
    """
    chunks = []
    md = []
    fence = None
    i = 0
    while i < len(lines):
        taken = None
        hit = _FENCE.match(lines[i])
        if hit:
            if fence is None:
                fence = len(hit.group(2))
            elif len(hit.group(2)) >= fence and not hit.group(3):
                fence = None
        start = _HOME_CENTRED.match(lines[i]) if fence is None and not hit else None
        if start:
            tag = start.group(1).lower()
            close = "</%s>" % tag
            end = i
            while end < len(lines) and close not in lines[end].lower():
                end += 1
            if end < len(lines):
                raw = "\n".join(lines[i:end + 1])
                cut = raw.lower().rindex(close)
                # The block is taken by whole lines, so a sentence standing
                # after the closing tag would go into the block and never be
                # seen. The front page is the whole README: nothing may be
                # dropped, so such a block is not one of ours.
                if not raw[cut + len(close):].strip():
                    inner = raw[raw.index(">") + 1:cut]
                    taken = _home_centred(tag, inner, ctx, logo)
                    if taken is not None:
                        i = end + 1
        if taken is None:
            md.append(lines[i])
            i += 1
            continue
        if md:
            chunks.append(("md", md))
            md = []
        chunks.append(taken)
    if md:
        chunks.append(("md", md))
    return chunks


def _home_section(section, lines):
    """The `##` section these lines end in, for the pattern that makes a card.

    A line starting with `#` inside a fenced block is a shell comment, not a
    heading, and the README's Quick Start is full of them.
    """
    fence = None
    for line in lines:
        hit = _FENCE.match(line)
        if hit:
            if fence is None:
                fence = len(hit.group(2))
            elif len(hit.group(2)) >= fence and not hit.group(3):
                fence = None
            continue
        if fence is not None:
            continue
        head = _HEADING.match(line)
        if head and len(head.group(1)) <= 2:
            section = slug(head.group(2))
    return section


def _home_feature(lines):
    """(the lines before it, the bold name, the sentence) of a feature block.

    A feature of the README is a paragraph that opens with a bold name and
    carries one sentence, with its screenshot centred underneath. The
    paragraph is the last one of the markdown before that picture; None means
    these lines do not end in one, and then nothing becomes a card.
    """
    end = len(lines)
    while end and not lines[end - 1].strip():
        end -= 1
    start = end
    while start and lines[start - 1].strip() and not _starts_block(lines[start - 1]):
        start -= 1
    para = lines[start:end]
    if not para or _starts_block(para[0]):
        return None  # a heading, a list or a table is not a feature's sentence
    named = re.match(r"^\*\*(?=\S)(.+?)(?<=\S)\*\*(.*)$", "\n".join(para).strip(), re.S)
    if not named:
        return None
    # The dash between the name and the sentence is the name's punctuation.
    sentence = re.sub(r"^\s*(?:\u2014|\u2013|-{1,2})?\s*", "", named.group(2))
    return (lines[:start], named.group(1), sentence)


def _home_card(picture, name, sentence, ctx):
    """One feature as a card: its picture on top, its name, its sentence.

    The name is a heading of the page, so the card is a place a link can aim
    at and headings() reports it; what it looks like is the card's business
    (the sheet styles `.card h3`).
    """
    return ('<article class="card">%s<h3 id="%s">%s</h3><p>%s</p></article>'
            % (picture, ctx.heading_id(name, 3), _inline(name, ctx),
               _inline(sentence, ctx)))


def _home_showcase(found, made):
    """Refuse a README that has feature blocks and no section to show them in.

    The cards are the feature blocks of the section HOME_FEATURES names. If
    that heading is renamed, the blocks are still in the file and still on the
    page - as loose paragraphs with their screenshots between them - and the
    front page would be published without its showcase, quietly. The README
    and this generator live in one repository, so a rename there stops the
    build here.
    """
    if found and not made:
        raise WikiError(
            "the README has %d feature block%s and no section #%s to show them in:\n"
            "  the front page's cards are the blocks of that section - a bold name, a\n"
            "  sentence, a centred picture - so the page would be published without the\n"
            "  showcase it is built around.\n"
            "  call the section by the name #%s slugs from again, or set HOME_FEATURES\n"
            "  in the generator to the section that holds the blocks."
            % (found, "" if found == 1 else "s", HOME_FEATURES, HOME_FEATURES))


def _home_document(chunks, ctx):
    """The chunks as one document: the hero, the cards, and the rest in order.

    The centred blocks at the top, down to the first markdown of the file, are
    the hero - the logo, the title, the one sentence and the badge rows. In the
    section the README's own #what-it-does names, every feature block becomes
    a card and a run of them one grid. Everything else is rendered where it
    stands.
    """
    out = []
    hero = []
    cards = []
    section = ""
    started = False  # the first markdown of the file closes the hero
    found = 0  # feature blocks anywhere in the file, and cards made of them
    made = 0
    i = 0
    while i < len(chunks):
        kind, payload = chunks[i]
        i += 1
        card = None
        if kind != "md":
            html = payload
        else:
            section = _home_section(section, payload)
            feature = None
            # A card needs the picture the README puts under the feature: the
            # next block has to be one, or the block after this paragraph
            # would be formatted into the card's picture slot.
            if i < len(chunks) and chunks[i][0] == "picture":
                feature = _home_feature(payload)
                if feature is not None:
                    found += 1
            if feature is None or section != HOME_FEATURES:
                html = _blocks(payload, ctx)
            else:
                # The lines before the feature's own paragraph are ordinary
                # markdown and are rendered first, so the ids stay in the
                # order the document has them.
                html = _blocks(feature[0], ctx)
                card = _home_card(chunks[i][1], feature[1], feature[2], ctx)
                made += 1
                i += 1
        if html:
            # The grid closes where the cards stop, so it stands inside the
            # section that holds them and not at the end of the document.
            if cards:
                out.append('<div class="cards">%s</div>' % "".join(cards))
                cards = []
            if kind == "md":
                started = True
            if started or kind == "md":
                out.append(html)
            else:
                hero.append(html)
        if card:
            cards.append(card)
    if cards:
        out.append('<div class="cards">%s</div>' % "".join(cards))
    if hero:
        out.insert(0, '<header class="hero">%s</header>' % "".join(hero))
    _home_showcase(found, made)
    return "".join(out)


def readme_html(text, images, logo):
    """The repository's README as the site's front page.

    The whole file, in its order - nothing selected, nothing reordered. What
    this adds to the ordinary render are the three peculiarities of the README:

    * **the centred HTML.** `<p align="center">` and `<h1 align="center">` are
      raw HTML, which the parser escapes to text everywhere else. Two forms are
      understood here: a centred picture (with the `<br><sub>` caption the
      README writes under its screenshots) and a centred line. Every other raw
      line - another tag, another attribute, a `<script>`, an `onerror=` -
      stays text, as before.
    * **the badges.** They are images of img.shields.io, a request to a third
      party at page load, which this site does not make. The picture is
      dropped and its label kept: in a link it becomes a chip that leads where
      the badge led, on its own a chip that says what it said.
    * **the links.** The README writes them from the repository's root
      (`docs/x.md`, `static/x.png`, `tdc-logo.png`), which home_link_target
      answers for - `images` comes from home_images and `logo` is the shipped
      copy of the one picture that does not lie in static/.

    On top of that, two things are presentation and no selection at all: the
    centred blocks at the top of the file are the page's hero, and in the
    section the README's own #what-it-does names, a bold name with a sentence
    and a centred picture under it is a card. An eleventh feature in the
    README becomes an eleventh card by itself.

    Raises WikiError when the file has feature blocks and no section for them
    (see _home_showcase): a front page published without its showcase would be
    a silent loss, and the README is in the same repository as this gate.
    """
    lines = text.replace("\r\n", "\n").replace("\t", "    ").split("\n")
    ctx = _Ctx(images, HOME_PAGE, links=home_link_target, scoped=False,
               net_note=False, reserved=SITE_SHELL_IDS)
    return _home_document(_home_chunks(lines, ctx, logo), ctx)


def _site_href(page, path):
    """A path under the site's root, as `page` has to write it.

    Every link of the site is relative: the front page lies in the root, every
    page of the guide one folder down, so the same extra is "assets/x" there
    and "../assets/x" here.
    """
    return ((SITE_HOME if page["url"] else "") + path) or "./"


def _site_style():
    """The site's own sheet: the product's Cyberpunk palette, the wiki's shapes.

    The palette and the fonts are the ones webui/static/css/theme-cyberpunk.css
    defines and the wiki's _style() already carries; the layout is the
    website's own - a header that stays, a register beside the text, reading
    width for the prose, pictures at page width.
    """
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
  --register: 280px;
  --reading: 780px;
  --header: 58px;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; background: var(--cp-bg); color: var(--cp-text);
  font-family: var(--font-sans); font-size: 16px; line-height: 1.68;
  -webkit-font-smoothing: antialiased;
  /* The footer belongs at the foot, also on a page shorter than the window. */
  min-height: 100vh; display: flex; flex-direction: column;
}
.shell { flex: 1; }
a { color: var(--cp-cyan); text-decoration: none; }
a:hover { color: var(--cp-magenta); text-decoration: underline; }
.skip {
  position: absolute; left: -9999px; top: 0; padding: 8px 12px; z-index: 40;
  background: var(--cp-card); border: 1px solid var(--cp-magenta);
  font-family: var(--font-mono); font-size: 12px;
}
.skip:focus { left: 8px; top: 8px; }

/* --- The header, the same on every page --- */
.site-header {
  position: sticky; top: 0; z-index: 30; display: flex; align-items: center;
  gap: 14px; padding: 8px 20px; min-height: var(--header);
  background: linear-gradient(180deg, var(--cp-bar-top), var(--cp-bar-bottom));
  border-bottom: 1px solid var(--cp-line);
}
.brand { display: flex; align-items: center; gap: 10px; color: inherit; }
.brand:hover { text-decoration: none; }
.brand-logo { width: 34px; height: 34px; border-radius: var(--radius); }
.brand-text b {
  display: block; font-family: var(--font-mono); font-size: 12.5px;
  letter-spacing: .1em; text-transform: uppercase; white-space: nowrap;
  background: linear-gradient(90deg, var(--cp-gold), var(--cp-amber) 45%, var(--cp-red));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.brand-text span {
  display: block; font-family: var(--font-mono); font-size: 9.5px;
  letter-spacing: .2em; text-transform: uppercase; color: var(--cp-text-dim);
}
.site-nav { display: flex; gap: 4px; margin-left: auto; }
.site-nav a {
  padding: 6px 12px; border: 1px solid transparent; border-radius: var(--radius);
  font-family: var(--font-mono); font-size: 11px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cp-text-muted);
}
.site-nav a:hover {
  color: var(--cp-magenta); border-color: var(--cp-magenta);
  background: rgba(255, 79, 216, .08); text-decoration: none;
}
.site-search { position: relative; width: 260px; }
#search {
  width: 100%; padding: 7px 10px; background: rgba(11, 7, 22, .9);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  color: var(--cp-text); font-family: var(--font-mono); font-size: 12px;
}
#search:focus {
  outline: none; border-color: var(--cp-magenta);
  box-shadow: 0 0 10px rgba(255, 79, 216, .25);
}
.results {
  position: absolute; top: calc(100% + 6px); right: 0; width: min(440px, 80vw);
  max-height: 60vh; overflow-y: auto; padding: 4px 0;
  background: var(--cp-card); border: 1px solid var(--cp-line);
  border-radius: var(--radius); box-shadow: 0 18px 40px -20px rgba(0, 0, 0, .9);
}
.results[hidden] { display: none; }
/* --- A hit: the page in mono capitals, its heading, the line itself --- */
.hit-note {
  margin: 0; padding: 7px 12px; color: var(--cp-text-dim);
  font-family: var(--font-mono); font-size: 9.5px; letter-spacing: .18em;
  text-transform: uppercase; overflow-wrap: break-word; word-break: break-word;
}
.hit-note:empty { display: none; }
.hit {
  display: block; padding: 8px 12px; border-left: 2px solid transparent;
  color: var(--cp-text);
}
.hit + .hit { border-top: 1px solid var(--cp-line); }
.hit:hover, .hit.is-active {
  background: var(--cp-raised); border-left-color: var(--cp-magenta);
  text-decoration: none;
}
.hit-page {
  display: block; font-family: var(--font-mono); font-size: 9.5px;
  letter-spacing: .15em; text-transform: uppercase; color: var(--cp-cyan);
}
.hit-head {
  display: block; margin-top: 1px; font-size: 13px; line-height: 1.4;
  color: var(--cp-text);
}
.hit-line {
  display: block; margin-top: 2px; font-family: var(--font-mono);
  font-size: 11px; line-height: 1.5; color: var(--cp-text-muted);
  overflow-wrap: break-word;
}
.hit mark {
  background: rgba(255, 79, 216, .18); color: var(--cp-magenta);
  border-radius: 2px; padding: 0 1px;
}
.register-toggle {
  display: none; padding: 6px 12px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  color: var(--cp-text-muted); font-family: var(--font-mono); font-size: 11px;
  letter-spacing: .1em; text-transform: uppercase; cursor: pointer;
}
.register-toggle:hover { color: var(--cp-magenta); border-color: var(--cp-magenta); }

/* --- The page: register beside the text --- */
.shell {
  display: grid; grid-template-columns: var(--register) minmax(0, 1fr);
  gap: 32px; max-width: 1320px; margin: 0 auto; padding: 0 20px;
}
body.home .shell { grid-template-columns: minmax(0, 1fr); }
.register {
  position: sticky; top: var(--header); align-self: start;
  max-height: calc(100vh - var(--header)); overflow-y: auto;
  padding: 22px 0 40px; border-right: 1px solid var(--cp-line);
}
.register-title {
  margin: 0 14px 10px; font-family: var(--font-mono); font-size: 9.5px;
  letter-spacing: .2em; text-transform: uppercase; color: var(--cp-text-dim);
}
.register-pages, .register-heads { list-style: none; margin: 0; padding: 0; }
.page-link, .head-link {
  display: block; padding: 5px 14px; border-left: 2px solid transparent;
  color: var(--cp-text-muted);
}
.page-link {
  font-family: var(--font-mono); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--cp-text);
}
.head-link { padding-left: 26px; font-size: 13.5px; color: var(--cp-text-dim); }
.page-link:hover, .head-link:hover {
  color: var(--cp-cyan); background: rgba(55, 224, 255, .06); text-decoration: none;
}
.page-entry.is-current > .page-link {
  color: var(--cp-magenta); border-left-color: var(--cp-magenta);
  background: rgba(255, 79, 216, .08);
}
.head-link.is-here { color: var(--cp-cyan); border-left-color: var(--cp-cyan); }
.register-heads { margin-bottom: 8px; }

/* --- The text --- */
.content { padding: 26px 0 64px; min-width: 0; }
.prose { max-width: var(--reading); }
body.home .prose { max-width: 980px; margin: 0 auto; }
h1, h2, h3, h4, h5, h6 {
  font-family: var(--font-mono); line-height: 1.3; scroll-margin-top: 76px;
}
h1 {
  margin: 6px 0 20px; font-size: 26px; letter-spacing: .04em; text-transform: uppercase;
  background: linear-gradient(90deg, var(--cp-gold), var(--cp-amber) 45%, var(--cp-red));
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
h2 {
  margin: 38px 0 12px; padding-bottom: 6px; font-size: 16px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cp-gold); border-bottom: 1px solid var(--cp-line);
}
h3 { margin: 26px 0 8px; font-size: 14px; letter-spacing: .08em; text-transform: uppercase; color: var(--cp-cyan); }
h4, h5, h6 { margin: 18px 0 6px; font-size: 12.5px; letter-spacing: .06em; color: var(--cp-green); }
p { margin: 12px 0; color: var(--cp-text-muted); }
strong { color: var(--cp-text); }
em { color: var(--cp-text); }
ul, ol { margin: 12px 0; padding-left: 24px; color: var(--cp-text-muted); }
li { margin: 5px 0; }
li > ul, li > ol { margin: 5px 0; }
hr { border: 0; border-top: 1px solid var(--cp-line); margin: 28px 0; }
code {
  font-family: var(--font-mono); font-size: 13px; color: var(--cp-cyan);
  background: rgba(55, 224, 255, .08); border: 1px solid rgba(55, 224, 255, .18);
  border-radius: 3px; padding: 1px 4px;
}
pre.code {
  font-size: 12.5px; line-height: 1.6; color: var(--cp-text-muted);
  background: rgba(11, 7, 22, .9); border: 1px solid var(--cp-line);
  border-left: 3px solid var(--cp-magenta);
  border-radius: 0 var(--radius) var(--radius) 0;
  padding: 12px 16px; overflow-x: auto; margin: 16px 0;
}
pre.code code { background: none; border: 0; padding: 0; color: inherit; font-size: inherit; }
blockquote {
  margin: 16px 0; padding: 8px 16px; background: rgba(255, 79, 216, .05);
  border-left: 3px solid var(--cp-magenta); border-radius: 0 var(--radius) var(--radius) 0;
}
blockquote p { margin: 4px 0; }
/* A wide table scrolls on its own instead of pushing the page sideways. */
table {
  border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px;
  display: block; overflow-x: auto;
}
th, td { border: 1px solid var(--cp-line); padding: 7px 10px; text-align: left; vertical-align: top; }
th {
  background: var(--cp-raised); color: var(--cp-text); font-family: var(--font-mono);
  font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
}
td { color: var(--cp-text-muted); }
tbody tr:nth-child(even) { background: rgba(27, 18, 50, .35); }
/* A screenshot at page width, not at its own: they are 1600 px wide. */
img {
  display: block; width: 100%; max-width: 100%; height: auto; margin: 18px 0;
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  box-shadow: 0 8px 24px -16px rgba(255, 79, 216, .35);
}
.no-image { font-family: var(--font-mono); font-size: 12px; color: var(--cp-text-dim); }
.net-note { font-family: var(--font-mono); font-size: 11px; color: var(--cp-text-dim); }
.note {
  padding: 10px 14px; background: rgba(255, 176, 0, .07);
  border: 1px solid rgba(255, 176, 0, .3); border-left: 3px solid var(--cp-amber);
  border-radius: var(--radius); color: var(--cp-text-muted);
}
pre.mermaid {
  margin: 20px 0; padding: 14px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  overflow-x: auto; text-align: left; font-family: var(--font-mono); font-size: 12px;
  color: var(--cp-text-dim); cursor: zoom-in;
}
pre.mermaid svg { max-width: 100%; height: auto; }
pre.mermaid.zoomed { cursor: zoom-out; }
/* Mermaid writes the fitted size into the style attribute, so the zoomed
   state has to beat it. */
pre.mermaid.zoomed svg { max-width: none !important; }

/* --- The two steps out of a page --- */
.pager {
  display: flex; gap: 14px; max-width: var(--reading); margin: 48px 0 0;
  padding-top: 20px; border-top: 1px solid var(--cp-line);
}
.pager a {
  flex: 1; padding: 10px 14px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
  color: var(--cp-text-muted);
}
.pager a:hover {
  border-color: var(--cp-magenta); background: var(--cp-raised); text-decoration: none;
}
.pager span {
  display: block; font-family: var(--font-mono); font-size: 9.5px;
  letter-spacing: .2em; text-transform: uppercase; color: var(--cp-text-dim);
}
.pager b { color: var(--cp-text); font-family: var(--font-mono); font-size: 12.5px; }
.pager-next { text-align: right; }

/* --- The footer --- */
.site-footer {
  margin-top: 40px; padding: 18px 20px 36px; border-top: 1px solid var(--cp-line);
  background: var(--cp-bar-bottom); font-family: var(--font-mono);
  font-size: 11px; letter-spacing: .05em; color: var(--cp-text-dim);
}
.site-footer p { margin: 4px 0; color: inherit; }
.site-footer code { background: none; border: 0; color: var(--cp-text-muted); }

/* --- The front page: the hero, the chips, the feature cards --- */
.hero { margin: 10px 0 22px; text-align: center; }
.hero figure { margin: 0; }
.hero figure img {
  width: auto; max-width: min(340px, 70%); margin: 0 auto 4px;
  border: 0; box-shadow: none;
}
.hero h1 {
  margin: 4px 0 8px; font-size: 30px; letter-spacing: .05em;
}
.hero .centred { max-width: 640px; margin: 0 auto 14px; font-size: 17px; }
.centred { text-align: center; }
.badges {
  display: flex; flex-wrap: wrap; justify-content: center; gap: 8px;
  margin: 14px 0;
}
.chip {
  display: inline-block; padding: 4px 11px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: 999px;
  font-family: var(--font-mono); font-size: 10.5px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cp-text-muted);
}
a.chip { color: var(--cp-cyan); }
a.chip:hover {
  color: var(--cp-magenta); border-color: var(--cp-magenta);
  background: rgba(255, 79, 216, .08); text-decoration: none;
}
/* A screenshot with the caption the README writes under it. */
figure.shot { margin: 20px 0; }
figure.shot figcaption {
  margin-top: 6px; font-family: var(--font-mono); font-size: 11.5px;
  line-height: 1.5; color: var(--cp-text-dim); text-align: center;
}
figure.shot figcaption sub { vertical-align: baseline; font-size: inherit; }
.cards {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px; margin: 22px 0 8px;
}
.card {
  display: flex; flex-direction: column; overflow: hidden;
  padding: 0 16px 14px; background: var(--cp-card);
  border: 1px solid var(--cp-line); border-radius: var(--radius);
}
.card:hover { border-color: var(--cp-magenta); }
.card figure { margin: 0; }
/* The picture sits on top of the card, edge to edge. */
.card img {
  width: calc(100% + 32px); max-width: none; margin: 0 -16px 12px;
  border: 0; border-bottom: 1px solid var(--cp-line); border-radius: 0;
  box-shadow: none;
}
.card h3 { margin: 0 0 6px; font-size: 12.5px; }
.card p { margin: 0; font-size: 14px; }

@media (max-width: 1000px) {
  .site-header { flex-wrap: wrap; }
  .site-search { order: 3; width: 100%; }
  .register-toggle { display: block; }
  body.guide .shell { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .register {
    display: none; position: static; max-height: none; border-right: 0;
    border-bottom: 1px solid var(--cp-line); padding: 14px 0;
  }
  .register.open { display: block; }
  .pager { flex-direction: column; }
  .pager-next { text-align: left; }
}
@media (max-width: 760px) {
  .cards { grid-template-columns: minmax(0, 1fr); }
}
/* On a phone the product's name is the widest thing on the page: it has to be
   allowed to wrap, or the whole document is wider than the window and every
   line of the guide scrolls sideways. */
@media (max-width: 640px) {
  .site-header { gap: 10px; padding: 8px 14px; }
  .brand { gap: 8px; }
  .brand-logo { width: 28px; height: 28px; }
  .brand-text b { white-space: normal; font-size: 11px; line-height: 1.3; }
  .brand-text span { display: none; }
  .site-nav { gap: 0; }
  .site-nav a { padding: 6px 7px; font-size: 10px; }
  .shell { padding: 0 14px; }
  .site-footer { padding: 16px 14px 28px; }
  h1 { font-size: 21px; }
  .hero h1 { font-size: 23px; }
}
"""


def _site_script():
    """What a page of the site does by itself: the search, the register, the
    diagrams.

    The only thing it ever asks for is the search index, a file of this site,
    and only once a reader has typed two characters. The hits are built as DOM
    nodes with textContent, never as markup: a line of the guide is text, in
    the page as well as in a hit, and the guide writes about `<script>` and
    `onerror=` at length.
    """
    return """
(function () {
  // --- The search: the index is a file, fetched when the reader first types ---
  var FROM = 2;          // a search from two characters: one letter is every page
  var MOST = 40;         // hits shown; more than a screenful is a list nobody reads
  var LEAD = 50, TAIL = 90;   // the words kept around the match in a long line
  var ECHO = 60;         // of the reader's own term, when nothing was found
  var box = document.querySelector('.site-search');
  var field = document.getElementById('search');
  var results = document.getElementById('results');
  var list = document.getElementById('search-hits');
  var count = document.getElementById('search-count');
  if (box && field && results && list && count) {
    var root = box.getAttribute('data-root') || '';
    var index = null;
    var asked = false;
    var nodes = [];
    var active = -1;

    // The count is a live region of the page, written here, not built: a
    // region made at the moment its text appears is not announced.
    function note(words) {
      count.textContent = words;
    }

    function hide() {
      results.hidden = true;
      count.textContent = '';
      list.textContent = '';
      nodes = [];
      active = -1;
      field.setAttribute('aria-expanded', 'false');
      field.removeAttribute('aria-activedescendant');
    }

    function show() {
      count.textContent = '';
      list.textContent = '';
      nodes = [];
      active = -1;
      results.hidden = false;
      field.setAttribute('aria-expanded', 'true');
      field.removeAttribute('aria-activedescendant');
    }

    // The text of a page goes in as text; only the piece that matched is
    // wrapped, in a <mark> this script makes itself.
    function fill(node, text, needle) {
      var at = needle ? text.toLowerCase().indexOf(needle) : -1;
      if (at < 0) {
        node.appendChild(document.createTextNode(text));
        return;
      }
      var from = 0;
      if (at > LEAD) {
        from = at - LEAD;
        var space = text.indexOf(' ', from);
        if (space >= 0 && space < at) { from = space + 1; }
      }
      var to = Math.min(text.length, at + needle.length + TAIL);
      node.appendChild(document.createTextNode(
        (from > 0 ? '\\u2026' : '') + text.slice(from, at)));
      var mark = document.createElement('mark');
      mark.textContent = text.slice(at, at + needle.length);
      node.appendChild(mark);
      node.appendChild(document.createTextNode(
        text.slice(at + needle.length, to) + (to < text.length ? '\\u2026' : '')));
    }

    function hitNode(record, needle, nth) {
      var page = index.pages[record[0]];
      var hit = document.createElement('a');
      hit.className = 'hit';
      hit.id = 'hit-' + nth;
      hit.setAttribute('role', 'option');
      hit.setAttribute('aria-selected', 'false');
      // The address of that section of that page, from where this page
      // stands: the current page's own hit is a jump inside it, because the
      // link resolves to the document that is already open.
      var href = root + page.url + '/' + (record[1] ? '#' + record[1] : '');
      hit.setAttribute('href', href);
      hit.addEventListener('click', function (event) {
        // A new tab (cmd, ctrl, shift, middle button) is the browser's
        // business, and the list stays as it is. An ordinary click is
        // followed here, so the list is gone before the reader arrives - on
        // a hit of this page the jump is a scroll, and the list would stand
        // over the section he was looking for.
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button) { return; }
        event.preventDefault();
        hide();
        location.assign(href);
      });
      var where = document.createElement('span');
      where.className = 'hit-page';
      where.textContent = page.title;
      hit.appendChild(where);
      var head = document.createElement('span');
      head.className = 'hit-head';
      fill(head, record[2], needle);
      hit.appendChild(head);
      var line = document.createElement('span');
      line.className = 'hit-line';
      fill(line, record[3], needle);
      hit.appendChild(line);
      return hit;
    }

    function mark(which) {
      active = which;
      nodes.forEach(function (node, i) {
        node.classList.toggle('is-active', i === which);
        node.setAttribute('aria-selected', i === which ? 'true' : 'false');
      });
      if (which >= 0 && nodes[which]) {
        field.setAttribute('aria-activedescendant', nodes[which].id);
        nodes[which].scrollIntoView({ block: 'nearest' });
      } else {
        field.removeAttribute('aria-activedescendant');
      }
    }

    function run() {
      var typed = field.value.trim();
      var needle = typed.toLowerCase();
      if (needle.length < FROM || !index) { hide(); return; }
      // A match in the heading is the section the reader means; a match in the
      // page's name alone is the weakest of the three.
      var heads = [], lines = [], names = [];
      for (var i = 0; i < index.records.length; i++) {
        var record = index.records[i];
        var page = index.pages[record[0]];
        if (!page) { continue; }
        if (record[2].toLowerCase().indexOf(needle) >= 0) {
          heads.push(record);
        } else if (record[3].toLowerCase().indexOf(needle) >= 0) {
          lines.push(record);
        } else if (page.title.toLowerCase().indexOf(needle) >= 0) {
          names.push(record);
        }
      }
      var found = heads.concat(lines, names);
      show();
      if (!found.length) {
        // The term is the reader's own text and is shown as text; a term
        // longer than the box is cut, so the line cannot run out of it.
        note('Nothing in the guide for \\u201c'
             + (typed.length > ECHO ? typed.slice(0, ECHO) + '\\u2026' : typed) + '\\u201d');
        return;
      }
      note(found.length > MOST
        ? MOST + ' of ' + found.length + ' hits'
        : found.length + (found.length === 1 ? ' hit' : ' hits'));
      found.slice(0, MOST).forEach(function (record, nth) {
        nodes.push(list.appendChild(hitNode(record, needle, nth)));
      });
    }

    function load() {
      if (asked) { return; }
      asked = true;
      fetch(root + 'search.json').then(function (answer) {
        if (!answer.ok) { throw new Error('the index answered ' + answer.status); }
        return answer.json();
      }).then(function (data) {
        index = data;
        run();          // the reader kept typing while it was on its way
      }).catch(function () {
        // Opened from a folder, fetch has no origin to ask; a published page
        // can lose the file to a half-finished deploy. Either way the field
        // says so rather than looking as if the guide had nothing.
        asked = false;  // the next keystroke may try again
        show();
        note('The search index could not be loaded - the offline wiki has a search of its own.');
      });
    }

    field.addEventListener('input', function () {
      if (field.value.trim().length < FROM) { hide(); return; }
      if (!index) { load(); return; }
      run();
    });

    field.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        field.value = '';
        hide();
        field.blur();
        return;
      }
      if (event.key === 'ArrowDown' && nodes.length) {
        event.preventDefault();
        mark(active + 1 >= nodes.length ? 0 : active + 1);
        return;
      }
      if (event.key === 'ArrowUp' && nodes.length) {
        event.preventDefault();
        mark(active <= 0 ? nodes.length - 1 : active - 1);
        return;
      }
      if (event.key === 'Enter') {
        var node = nodes[active >= 0 ? active : 0];
        if (!node) { return; }
        event.preventDefault();
        var target = node.getAttribute('href');
        hide();
        location.assign(target);
      }
    });

    // Anywhere else on the page: the list is not a layer to click away twice
    document.addEventListener('click', function (event) {
      if (event.target && !box.contains(event.target)) { hide(); }
    });

    // "/" is the way to the field, as in the wiki - unless somebody is typing
    document.addEventListener('keydown', function (event) {
      if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) { return; }
      var at = event.target || {};
      var tag = (at.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || at.isContentEditable) {
        return;
      }
      event.preventDefault();
      field.focus();
    });
  }

  // --- The register on a narrow screen: a button instead of a column ---
  var toggle = document.querySelector('.register-toggle');
  var register = document.getElementById('register');
  if (toggle && register) {
    toggle.addEventListener('click', function () {
      var open = register.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    register.addEventListener('click', function (event) {
      if (event.target.closest('a')) {
        register.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // --- Where the reader is inside the page ---
  var heads = Array.prototype.slice.call(document.querySelectorAll('.prose h2[id]'));
  var links = Array.prototype.slice.call(document.querySelectorAll('.register .head-link'));
  function mark(id) {
    links.forEach(function (link) {
      link.classList.toggle('is-here', link.getAttribute('href') === '#' + id);
    });
  }
  function spy() {
    var current = heads.length ? heads[0].id : null;
    for (var i = 0; i < heads.length; i++) {
      if (heads[i].getBoundingClientRect().top <= 120) { current = heads[i].id; } else { break; }
    }
    if (current) { mark(current); }
  }
  if (heads.length && links.length) {
    window.addEventListener('scroll', function () {
      window.requestAnimationFrame(spy);
    }, { passive: true });
    if (location.hash.length > 1) { mark(location.hash.slice(1)); } else { spy(); }
  }

  // --- A diagram at full size: a wide one is unreadable fitted into a column ---
  var FIT = 'Click to see the diagram at full size';
  var FULL = 'Click to fit the diagram into the page';
  Array.prototype.forEach.call(document.querySelectorAll('pre.mermaid'), function (pre) {
    pre.title = FIT;
    pre.addEventListener('click', function () {
      var svg = pre.querySelector('svg');
      if (!svg) { return; }
      var zoom = !pre.classList.contains('zoomed');
      pre.classList.toggle('zoomed', zoom);
      var box = svg.viewBox && svg.viewBox.baseVal;
      svg.style.width = zoom && box && box.width ? Math.round(box.width) + 'px' : '';
      pre.title = zoom ? FULL : FIT;
    });
  });
})();
"""


def _site_header(page):
    """Logo and title on the left, the three ways and the search on the right."""
    out = ['<header class="site-header">',
           '<a class="brand" href="%s">' % _site_href(page, ""),
           '<img class="brand-logo" src="%s" alt="" width="34" height="34">'
           % _site_href(page, SITE_LOGO),
           '<span class="brand-text"><b>%s</b><span>%s</span></span></a>'
           % (TITLE, SITE_SUBTITLE)]
    if page["url"]:
        out.append('<button class="register-toggle" type="button" aria-expanded="false"'
                   ' aria-controls="register">Contents</button>')
    out.append('<nav class="site-nav" aria-label="Site">')
    out.append('<a href="%s">Guide</a>' % _site_href(page, page_url("README.md") + "/"))
    out.append('<a href="%s" target="_blank" rel="noopener">GitHub</a>' % REPO_URL)
    out.append('<a href="%s" download>Offline wiki</a>' % _site_href(page, SITE_WIKI))
    out.append('</nav>')
    # The field is the shell's; the index it reads is a file of this site, and
    # the root is where this page has to look for it. The field is a combobox
    # over the list of hits, so a screen reader is told that a list opened,
    # which hit is the current one, and how many there are (the count is a
    # polite live region of its own).
    out.append('<div class="site-search" data-root="%s">'
               '<input id="search" type="search" placeholder="Search the guide"'
               ' autocomplete="off" spellcheck="false" aria-label="Search the guide"'
               ' role="combobox" aria-expanded="false" aria-autocomplete="list"'
               ' aria-controls="search-hits">'
               '<div id="results" class="results" hidden>'
               '<p id="search-count" class="hit-note" role="status" aria-live="polite"></p>'
               '<div id="search-hits" class="hits" role="listbox" aria-label="Search hits">'
               '</div></div></div>' % _site_href(page, ""))
    out.append('</header>')
    return "".join(out)


def _site_register(page, pages):
    """Every page of the index, the one being read marked, its ## headings under it.

    The same list on every page, so only the marker says where one stands - and
    the jump targets are the headings of this page, which are the ones a reader
    can reach without loading another file.
    """
    out = ['<aside class="register" id="register"><nav aria-label="Guide">',
           '<p class="register-title">The guide</p>', '<ul class="register-pages">']
    for other in pages:
        current = other["url"] == page["url"]
        out.append('<li class="page-entry%s">' % (" is-current" if current else ""))
        out.append('<a class="page-link" href="%s"%s>%s</a>'
                   % (_site_href(page, other["url"] + "/"),
                      ' aria-current="page"' if current else "",
                      esc(site_label(other))))
        if current:
            subs = [(hid, text) for level, hid, text in page["headings"] if level == 2]
            if subs:
                out.append('<ul class="register-heads">')
                for hid, text in subs:
                    out.append('<li><a class="head-link" href="#%s">%s</a></li>'
                               % (hid, esc(text)))
                out.append("</ul>")
        out.append("</li>")
    out.append("</ul></nav></aside>")
    return "".join(out)


def _site_pager(page):
    """The two steps out of a page, along the index's order."""
    if not page["prev"] and not page["next"]:
        return ""
    out = ['<nav class="pager" aria-label="Pages">']
    for which, label in (("prev", "Previous"), ("next", "Next")):
        other = page[which]
        if other:
            out.append('<a class="pager-%s" href="%s"><span>%s</span><b>%s</b></a>'
                       % (which, _site_href(page, other["url"] + "/"), label,
                          esc(site_label(other))))
    out.append("</nav>")
    return "".join(out)


def _site_footer(page, built_at, commit):
    """When it was built, from what, and where the page itself is written.

    No local path and no machine name: this is published to the world, and it
    is what a reader quotes in an issue.
    """
    parts = ['Built <time datetime="%s">%s UTC</time>'
             % (built_at.strftime("%Y-%m-%dT%H:%M:%SZ"), built_at.strftime("%Y-%m-%d %H:%M"))]
    if commit:
        parts.append("commit <code>%s</code>" % commit)
    parts.append("diagrams by Mermaid %s (MIT)" % MERMAID_VERSION)
    source = REPO_BLOB + ("docs/" + page["name"] if page["url"] else page["name"])
    return ('<footer class="site-footer"><p>%s</p><p>'
            '<a href="%s" target="_blank" rel="noopener">Read this page in the repository</a>'
            ' &middot; <a href="%s" download>Download the offline wiki</a>'
            ' &middot; %s</p></footer>'
            % (" &middot; ".join(parts), source, _site_href(page, SITE_WIKI), TITLE))


def site_page(page, pages, built_at, commit):
    """One page of the website as a whole HTML document.

    `page` carries `name` (the markdown it came from), `url` (its folder, ""
    for the front page), `title`, `html` (the rendered markdown), `headings`
    and `prev`/`next` (the neighbouring pages or None). `pages` is the guide in
    the index's order, for the register.

    The style sheet and the script are shipped files, so a reader who walks
    through the guide loads them once; the Mermaid bundle is 2.5 MB and is
    asked for only by a page that actually carries a diagram.
    """
    home = not page["url"]
    label = esc(page["title"])
    # The product's name once: the guide's index carries it in its own h1
    # already, and "X - X - Y" in a browser tab and a bookmark is noise.
    if home:
        title = TITLE
    elif page["title"].startswith(TITLE):
        title = label
    else:
        title = "%s &mdash; %s" % (label, TITLE)
    out = ['<!DOCTYPE html>', '<html lang="en" data-theme="cyberpunk">', '<head>',
           '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>%s</title>' % title,
           '<link rel="icon" href="%s">' % SITE_ICON,
           '<link rel="stylesheet" href="%s">' % _site_href(page, SITE_STYLE),
           '</head>',
           '<body class="%s">' % ("home" if home else "guide"),
           '<a class="skip" href="#content">Skip to the content</a>',
           _site_header(page),
           '<div class="shell">']
    if not home:
        out.append(_site_register(page, pages))
    out.append('<main class="content" id="content">')
    out.append('<article class="prose">')
    out.append(page["html"])
    out.append("</article>")
    out.append(_site_pager(page))
    out.append("</main></div>")
    out.append(_site_footer(page, built_at, commit))
    if '<pre class="mermaid"' in page["html"]:
        out.append('<script src="%s" data-version="%s"></script>'
                   % (_site_href(page, SITE_MERMAID), MERMAID_VERSION))
        out.append("<script>%s</script>" % _mermaid_init())
    out.append('<script src="%s" defer></script>' % _site_href(page, SITE_SCRIPT))
    out.append("</body></html>")
    return "\n".join(out)


def _require_pictures(label, text, static_dir, prefix):
    """Every picture a page names has to be a file that static/ really has.

    The wiki draws a placeholder for a picture it cannot embed, which is honest
    in one file that carries its images. On a published page the frame would be
    broken for every reader and the request a 404, so the build stops and says
    which page wants which file.

    Every reference under the prefix is checked, not only the `.png` the site
    copies: a `static/x.gif` becomes a link to that path on github.com, where a
    file the repository does not have is a 404 just the same - and static/ is
    the repository, so this directory is the one place that can answer for
    both. (A reference to a picture somewhere else on the web is not checked
    here: it is nothing this build ships, and the renderer names it instead of
    showing a broken frame.)
    """
    for ref in re.findall(r'(?:\]\(|src=")%s([^)"#\s]+)' % re.escape(prefix), text, re.I):
        if not os.path.isfile(os.path.join(static_dir, ref)):
            raise WikiError(
                "%s names the picture %s%s, which is not there:\n"
                "  the website ships every screenshot as its own file, so a missing one is\n"
                "  a broken image on a published page, not a placeholder.\n"
                "  put the file in %s, or take the reference out of the page, and build again."
                % (label, prefix, ref, static_dir))


def _write_text(out_dir, rel, text):
    """One written file of the site, its folder made on the way."""
    path = os.path.join(out_dir, rel.replace("/", os.sep))
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_copy(out_dir, rel, source):
    """A shipped file, copied in pieces: the demo video is 10 MB."""
    path = os.path.join(out_dir, rel.replace("/", os.sep))
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    with open(source, "rb") as src, open(path, "wb") as dst:
        while True:
            chunk = src.read(1024 * 256)
            if not chunk:
                break
            dst.write(chunk)


def _site_entry(rel):
    """Whether a line of a manifest names a file inside the folder it lies in.

    The list is a file in the build folder, so it is an input, not a fact:
    whoever can add a line to it would otherwise have the next build delete
    whatever the builder can reach. An entry is a path this build could have
    written - relative, downwards only, no drive and no share.
    """
    if not rel or rel[:1] in ("/", "\\"):
        return False
    if ":" in rel:  # a drive letter (C:\x, c:x) or something with a scheme
        return False
    return all(part not in ("", ".", "..") for part in rel.replace("\\", "/").split("/"))


def _inside(out_dir, path):
    """Whether path lies under out_dir - and is not out_dir itself."""
    root = os.path.abspath(out_dir)
    full = os.path.abspath(path)
    try:
        # commonpath, not startswith: "/a/bc" does not lie under "/a/b".
        return full != root and os.path.commonpath([root, full]) == root
    except ValueError:
        return False  # different drives on Windows, or a mix of kinds


def _site_manifest(out_dir):
    """What an earlier build wrote into out_dir, or None when none did.

    None is the answer for a folder that was never a site of ours, and for a
    list that cannot be one - unreadable, or naming anything but a file inside
    the folder. The caller refuses the folder either way: a list we cannot
    trust is not a list, and a folder we cannot account for is not swept.
    """
    path = os.path.join(out_dir, SITE_MANIFEST)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [line.strip() for line in fh]
    except (OSError, UnicodeDecodeError):
        return None
    entries = [line for line in lines if line]
    return entries if all(_site_entry(rel) for rel in entries) else None


def _drop_stale(out_dir, previous, written):
    """Whatever the build before this one wrote and this one did not.

    A renamed page would otherwise keep its old folder, which the register no
    longer names but the upload still publishes - a page of the guide as it was
    some commits ago, with no way to tell. Only the paths of that earlier build
    are considered, and only inside the build folder: a file this build never
    wrote is not ours to delete, and neither is anything outside.
    """
    keep = set(written)
    for rel in previous:
        if rel in keep or not _site_entry(rel):
            continue
        path = os.path.join(out_dir, rel.replace("/", os.sep))
        if not _inside(out_dir, path):
            continue
        if os.path.islink(path) or os.path.isfile(path):
            os.remove(path)
        # A listed path that is a directory now is left where it is. This build
        # writes files only, so a directory in the place of one was made by
        # somebody else, and emptying it would mean deleting what is in it
        # without any list saying it is ours. It carries no index.html, so it
        # publishes nothing, and the list of this build no longer names it.
        folder = os.path.dirname(path)
        while _inside(out_dir, folder) and os.path.isdir(folder) and not os.listdir(folder):
            os.rmdir(folder)
            folder = os.path.dirname(folder)


_SITE_PAGE_LINK = re.compile(r'href="(\.\./)?([A-Za-z0-9][A-Za-z0-9._-]*)/(?:#[^"]*)?"')


def _gate_page_links(written_pages, urls):
    """Refuse a link to a folder that is no page of this site.

    site_link_target turns a relative .md path into "../<folder>/", whether the
    page behind it is published or not: a link to a page the index does not
    order, or to one that was renamed, becomes a folder this build does not
    write - a 404 on the published site, with `make site` exiting 0 and the
    test that would catch it running in the other workflow.

    `written_pages` are the pages as they will be written, the front page
    included; it writes the same link one level up ("rizin/" instead of
    "../rizin/"), so the depth of the page decides which form to read. Only
    single-folder links are read: an anchor, an asset, the offline wiki, the
    front page and a link to github.com or the web have no such shape.
    """
    for page in written_pages:
        inside_a_folder = bool(page["url"])
        for found in _SITE_PAGE_LINK.finditer(page["html"]):
            if bool(found.group(1)) != inside_a_folder:
                continue
            folder = found.group(2)
            if folder in urls or folder == SITE_ASSETS:
                continue
            raise WikiError(
                "%s links %s, which is no page of this site.\n"
                "  every relative .md path becomes a folder of the site, so a link\n"
                "  to a page that is not published is a dead link on it. the pages\n"
                "  are the ones docs/README.md orders: %s"
                % (page["name"], found.group(0)[len('href="'):-1],
                   ", ".join(sorted(urls))))


def build_site(docs_dir, static_dir, mermaid_path, out_dir, readme_path, logo_path,
               wiki_path):
    """Build the website into out_dir and return what it wrote.

    One address per entry of the index, plus the front page: the README of
    the repository, /guide/ from docs/README.md and one folder per page of the
    guide, in the index's order - each an index.html, so /rizin/ is an address
    a reader can keep.
    Beside them the shipped extras: the style sheet, the script, the search
    index, the pinned Mermaid bundle, every screenshot, the demo video, the
    logo, the offline wiki for download and .nojekyll (the publishing workflow
    uploads the folder as an artifact, which Pages serves as it stands; the
    file is for a folder published some other way - a deployment from a branch
    runs Jekyll over it unless the file says not to).

    Everything that can fail is checked before the first file is written, and a
    WikiError says what to do: a missing index, a page the index links but
    docs/ does not have, a picture static/ does not have, a Mermaid copy that
    is missing or changed, a missing README, logo or offline wiki, and a build
    folder that holds files no build of ours wrote. The returned paths are
    relative to out_dir, in sorted order, and are also left in the folder as
    SITE_MANIFEST, which is the only thing the next build will sweep.
    """
    index_path = os.path.join(docs_dir, "README.md")
    if not os.path.isfile(index_path):
        raise WikiError("no index to read the page order from: %s/README.md" % docs_dir)
    # The wiki's own gate, first: a site whose diagrams are dead text is worse
    # than no site, and nothing may be written before it is passed.
    read_mermaid(mermaid_path)
    for path, what in ((readme_path, "the README the front page is made of"),
                       (logo_path, "the logo the header carries"),
                       (wiki_path, "the offline wiki the header offers for download"
                                   " - build it first (make docs)")):
        if not os.path.isfile(path):
            raise WikiError("%s is missing: %s" % (what, path))
    # Whose folder this is. A list of ours means we may sweep what is on it; no
    # list and something in the folder means it is somebody else's, and the
    # dozens of files of a website do not belong in it.
    previous = _site_manifest(out_dir)
    if previous is None and os.path.isdir(out_dir) and os.listdir(out_dir):
        raise WikiError(
            "the build folder holds files that no build of this site wrote: %s\n"
            "  a build writes one page per entry of docs/README.md, the front page\n"
            "  and the extras into it, and keeps a list\n"
            "  (%s) of them, so that the next build can take back exactly what it put\n"
            "  there; without that list nothing here can be told apart from your own\n"
            "  files. build into an empty folder (make site SITE_DIR=...), or empty\n"
            "  this one yourself." % (out_dir, SITE_MANIFEST))
    images = file_images(static_dir)
    with open(index_path, encoding="utf-8") as fh:
        order = page_order(fh.read())
    # Every markdown of docs/ is a page of the index, and every page of the
    # index is a markdown of docs/. A file nobody links would be dropped in
    # silence - `make site` would exit 0 and the page would simply have no
    # address - and the suite that catches it runs in another workflow than the
    # one that publishes. docs/superpowers/ holds drafts and is not a page.
    present = set(name for name in os.listdir(docs_dir)
                  if name.lower().endswith(".md")
                  and os.path.isfile(os.path.join(docs_dir, name)))
    forgotten = sorted(present - set(order))
    if forgotten:
        raise WikiError(
            "docs/README.md does not link %s, so %s would have no address.\n"
            "  the index is what orders the pages of the guide: link the page\n"
            "  there (it is also what the offline wiki and the register follow),\n"
            "  or take the file out of docs/."
            % (", ".join(forgotten), "they" if len(forgotten) > 1 else "it"))
    pages = []
    taken = {}
    for name in order:
        path = os.path.join(docs_dir, name)
        if not os.path.isfile(path):
            raise WikiError("docs/README.md links %s, which does not exist" % name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        _require_pictures("docs/" + name, text, static_dir, "../static/")
        html = render_markdown(text, images, page=name, links=site_link_target,
                               scoped=False, net_note=False,
                               reserved=SITE_SHELL_IDS)
        found = headings(html)
        url = page_url(name)
        if url in taken:
            raise WikiError("docs/%s and docs/%s would both be published as /%s/"
                            % (taken[url], name, url))
        taken[url] = name
        pages.append({"name": name, "url": url,
                      "title": found[0][2] if found and found[0][0] == 1 else url,
                      "html": html, "headings": found, "text": text})
    # The index's order is the guide's **Next:** chain, and that chain closes:
    # the page before the index is the last page of the guide.
    for i, page in enumerate(pages):
        page["prev"] = pages[i - 1]
        page["next"] = pages[(i + 1) % len(pages)]
    with open(readme_path, encoding="utf-8") as fh:
        front_text = fh.read()
    front_name = os.path.basename(readme_path)
    _require_pictures(front_name, front_text, static_dir, "static/")
    # The front page is the whole README, rendered: its centred HTML as the
    # hero and as pictures, its badges as chips, its feature blocks as cards.
    front_html = readme_html(front_text, home_images(static_dir), SITE_LOGO)
    front = {"name": front_name, "url": "", "title": TITLE, "html": front_html,
             "headings": headings(front_html), "prev": None, "next": None,
             "text": front_text}
    # Every page link of every page reaches a page this build writes
    _gate_page_links([front] + pages, set(taken))

    # UTC, and not utcnow(): that one is deprecated in 3.12 (the version the
    # publishing workflow pins) and scheduled for removal. tzinfo is dropped
    # again so the footer's strftime stays what it was, to the byte.
    built_at = datetime.datetime.now(datetime.timezone.utc).replace(
        tzinfo=None, microsecond=0)
    commit = short_commit()
    # The index is every page of the guide: the search field searches the
    # guide, and the front page is the README, whose own text is the guide's
    # entrance rather than part of it.
    index = json.dumps(search_index(pages), ensure_ascii=False,
                       separators=(",", ":"), sort_keys=True)
    texts = [(".nojekyll", ""), (SITE_STYLE, _site_style()), (SITE_SCRIPT, _site_script()),
             (SITE_SEARCH, index + "\n"),
             ("index.html", site_page(front, pages, built_at, commit))]
    for page in pages:
        texts.append(("%s/index.html" % page["url"], site_page(page, pages, built_at, commit)))
    copies = [(SITE_LOGO, logo_path), (SITE_MERMAID, mermaid_path), (SITE_WIKI, wiki_path)]
    demo = os.path.join(static_dir, os.path.basename(DEMO_GIF))
    if os.path.isfile(demo):
        copies.append((SITE_DEMO, demo))
    for name in images:
        copies.append(("%s/%s" % (SITE_IMG, name), os.path.join(static_dir, name)))

    # The list goes in before the first file and names itself, so that a build
    # broken off in the middle still leaves a folder the next build can account
    # for - and so that the build after this one can take back exactly what
    # this one put there.
    written = sorted([rel for rel, _ in texts] + [rel for rel, _ in copies]
                     + [SITE_MANIFEST])
    _write_text(out_dir, SITE_MANIFEST, "\n".join(written) + "\n")
    for rel, text in texts:
        _write_text(out_dir, rel, text)
    for rel, source in copies:
        _write_copy(out_dir, rel, source)
    if previous:
        _drop_stale(out_dir, previous, written)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build the offline wiki (one HTML file) from docs/, or with "
                    "--site the documentation website (one folder per page).")
    parser.add_argument("--docs", default=os.path.join(ROOT, "docs"))
    parser.add_argument("--static", default=os.path.join(ROOT, "static"))
    parser.add_argument("--mermaid", default=os.path.join(ROOT, "scripts", "wiki", "mermaid.min.js"))
    parser.add_argument("-o", "--out", default=os.path.join(ROOT, "webui", "static", "wiki.html"))
    parser.add_argument("--site", metavar="DIR", default=None,
                        help="build the website into DIR instead of the wiki; the "
                             "wiki at --out is shipped as the download, so build it first")
    parser.add_argument("--readme", default=os.path.join(ROOT, "README.md"),
                        help="the markdown the site's front page is made of (--site)")
    parser.add_argument("--logo", default=os.path.join(ROOT, "tdc-logo.png"),
                        help="the picture the site's header carries (--site)")
    args = parser.parse_args(argv)
    if args.site:
        try:
            written = build_site(args.docs, args.static, args.mermaid, args.site,
                                 args.readme, args.logo, args.out)
        except WikiError as err:
            sys.stderr.write("[site] %s\n" % err)
            return 1
        size = sum(os.path.getsize(os.path.join(args.site, rel.replace("/", os.sep)))
                   for rel in written)
        # The folder as it was named, unless it lies under the repository - a
        # path of "../../../.." tells a reader nothing.
        where = os.path.relpath(args.site, ROOT)
        if where.startswith(".."):
            where = args.site
        sys.stdout.write("[site] %s: %d pages, %d files, %.1f MB\n"
                         % (where,
                            len([rel for rel in written if rel.endswith("index.html")]),
                            len(written), size / (1024.0 * 1024.0)))
        return 0
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
