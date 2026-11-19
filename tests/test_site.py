"""The website: the same guide, one address per page, on GitHub Pages.

The offline wiki is one file, so a link to another page is a jump inside it, an
anchor carries the page it stands on, and a screenshot is a `data:` URI. The
website is the other shape of the same text: every page is its own file in its
own folder, so a link to another page is `../<folder>/`, an anchor is the
heading's own slug (the one GitHub makes, which the docs already write by hand)
and a screenshot is a file next to the page.

What is held here is the renderer's side of that: where a link points, what an
anchor is called, where a picture comes from - and that the wiki's own output
did not move a byte while the second output was taught.

On top of that the shell and the writer: one address per page of the index plus
the front page, the register that marks where the reader is, prev/next along
the index's order, the shipped extras, and the promises a published page breaks
silently - a link that resolves to nothing, a picture that is a 404 instead of a
placeholder, a diagram bundle on a page that has no diagram, and anything at all
that the browser would fetch from a server that is not this one.

And the front page, which is the repository's README whole: its centred raw
HTML as a hero and as pictures, its badges as chips with no request to a
third party, and its feature blocks as cards - recognised as a pattern, so an
eleventh feature in the README is an eleventh card.

And the search: the index as a file of the site, with the anchors of the
written pages rather than the wiki's scoped ones, and what the field does in a
browser - run against assets/site.js in node with a small DOM stub.

One module-scoped fixture builds the real website once (every page of the index,
every screenshot of static/ and the demo video, some tens of MB of copies);
every other test builds a small site in tmp_path.

Nothing here counts the guide. The number of pages, of screenshots and of
diagrams is read from docs/ and from the index's own order, so a new page of
the guide is a new address here by itself: a test that had to be bumped from
fourteen to fifteen would only have to be bumped again.
"""

import datetime
import hashlib
import html as html_module
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
# The address the site is published at, as the spec writes it. It is one
# address, so it is one spelling: the badge of the README, the two lines that
# link it and the test of the publication at the end of this file say the same
# string.
SITE_URL = "https://benjitrapp.github.io/transportable-detonation-chamber/"


def _load_generator():
    """scripts/build-wiki.py is a script, not a package: load it by path."""
    path = os.path.join(ROOT, "scripts", "build-wiki.py")
    spec = importlib.util.spec_from_file_location("tdc_build_site", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


site = _load_generator()


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()

# The smallest valid PNG: 1x1, fully transparent (as in tests/test_wiki.py).
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6300010000050001"
    "0d0a2db40000000049454e44ae426082")

# --- The byte-for-byte fixture of the wiki's output --------------------------
# One page of markdown that touches everything the two outputs disagree about
# (a link to another page, an anchor of its own, a link out of docs/, a
# picture) plus the blocks around it, and the HTML the generator produced for
# it before the website was taught. The wiki is the documentation of a machine
# with no network: its output may not move by a byte for the website's sake.

WIKI_FIXTURE = """# Rizin

What it answers, in **bold** and `code`.

![A shot](../static/shot.png)

## Limits

- one
  - nested
- two

See [Web UI](web-ui.md#charts), the [index](README.md), its own
[limits](#limits) and the [Vagrantfile](../Vagrantfile.utm).

| Flag | What it does |
|---|---|
| `-a` | all |

## Limits

```mermaid
graph TD
  A --> B
```

> A note, with *italics*.
"""

WIKI_IMAGES = {"shot.png": "data:image/png;base64,AAAA"}

WIKI_HTML = (
    '<h1 id="rizin">Rizin</h1>'
    '<p>What it answers, in <strong>bold</strong> and <code>code</code>.</p>'
    '<p><img src="data:image/png;base64,AAAA" alt="A shot" loading="lazy"></p>'
    '<h2 id="rizin--limits">Limits</h2>'
    '<ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>'
    '<p>See <a href="#web-ui--charts">Web UI</a>, the <a href="#readme">index</a>,'
    ' its own\n<a href="#rizin--limits">limits</a> and the '
    '<a href="https://github.com/BenjiTrapp/transportable-detonation-chamber/'
    'blob/main/Vagrantfile.utm" target="_blank" rel="noopener">Vagrantfile</a>'
    '<span class="net-note"> (needs network access, which the VM does not have)'
    '</span>.</p>'
    '<table><thead><tr><th>Flag</th><th>What it does</th></tr></thead><tbody>'
    '<tr><td><code>-a</code></td><td>all</td></tr></tbody></table>'
    '<h2 id="rizin--limits-2">Limits</h2>'
    '<pre class="mermaid">\ngraph TD\n  A --&gt; B\n</pre>'
    '<blockquote><p>A note, with <em>italics</em>.</p></blockquote>')


def _site_html(text, images=None, page="rizin.md"):
    """One page as the website renders it: other files, bare anchors, no note."""
    return site.render_markdown(text, images or {}, page=page,
                                links=site.site_link_target, scoped=False,
                                net_note=False)


# --- Building a website ------------------------------------------------------


class _Built(object):
    """A built website: where it is and what it wrote."""

    def __init__(self, directory, written):
        self.dir = directory
        self.written = written

    def read(self, rel):
        with open(os.path.join(self.dir, rel), encoding="utf-8") as fh:
            return fh.read()

    def pages(self):
        """The written pages, every one of them an index.html of a folder."""
        return sorted(rel for rel in self.written if rel.endswith("index.html"))


def _fixture_site(tmp_path, pages, images=("shot.png",), readme=None, wiki=True,
                  logo=True, mermaid=None, out="site", unlisted=None):
    """A small website in tmp_path: docs/, static/, a README, a logo, a wiki.

    `pages` maps a file name to its markdown; the index links them in order, so
    page_order sees them the way it sees the real guide. `readme`, `wiki`,
    `logo` and `mermaid` can be taken away or spoiled, which is what the build
    has to refuse: False leaves the file out, and a string is written as the
    file's content (a Mermaid copy that is not the pinned one). `unlisted` puts
    markdown into docs/ that the index does not link - the page the site would
    silently drop.
    """
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    index = ["# Fixture index", "", "An index for the tests.", ""]
    for name in pages:
        index.append("- [%s](%s)" % (name, name))
    (docs / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    for name, body in pages.items():
        # A page with no body is one the index links and docs/ does not have:
        # the ghost the build has to refuse.
        if body is None:
            continue
        (docs / name).write_text(body, encoding="utf-8")
    for name, body in (unlisted or {}).items():
        (docs / name).write_text(body, encoding="utf-8")
    # The fixtures of one test share tmp_path, so a page an earlier call wrote
    # has to be taken away again rather than only left out of this one
    for found in os.listdir(str(docs)):
        if found.lower().endswith(".md") and found != "README.md" \
                and found not in pages and found not in (unlisted or {}):
            os.remove(os.path.join(str(docs), found))
    static = tmp_path / "static"
    static.mkdir(exist_ok=True)
    for name in images:
        (static / name).write_bytes(PNG)
    (static / "demo.gif").write_bytes(b"GIF89a")

    def place(path, content):
        """Write the ingredient, or take it away when it is not wanted.

        The fixtures of one test share tmp_path, so "not there" has to be made,
        not only left out.
        """
        if content is False:
            if os.path.exists(str(path)):
                os.remove(str(path))
        elif isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    front = tmp_path / "README.md"
    place(front, False if readme is False else (readme or "# Front\n\nThe product.\n"))
    logo_path = tmp_path / "tdc-logo.png"
    place(logo_path, PNG if logo else False)
    offline = tmp_path / "wiki.html"
    place(offline, "<!DOCTYPE html><title>Offline wiki</title>" if wiki else False)
    bundle = MERMAID
    if mermaid is not None:
        bundle = tmp_path / "mermaid.min.js"
        place(bundle, mermaid)
        bundle = str(bundle)
    written = site.build_site(str(docs), str(static), bundle, str(tmp_path / out),
                              str(front), str(logo_path), str(offline))
    return _Built(str(tmp_path / out), written)


def _tree(directory):
    """Every file under `directory` with its content, by relative path.

    What a refused build may not change: a folder of an earlier build has to
    come out of it exactly as it went in.
    """
    found = {}
    for folder, _, names in os.walk(directory):
        for name in names:
            path = os.path.join(folder, name)
            with open(path, "rb") as fh:
                found[os.path.relpath(path, directory)] = hashlib.sha256(fh.read()).hexdigest()
    return found


@pytest.fixture(scope="module")
def real_site(tmp_path_factory):
    """The website of this repository, built once for the whole module.

    The offline wiki is git-ignored and may not be built yet, so the download
    gets a stub here - everything else is the real guide, the real README and
    the real screenshots.
    """
    base = tmp_path_factory.mktemp("site")
    offline = base / "wiki.html"
    offline.write_text("<!DOCTYPE html><title>Offline wiki</title>", encoding="utf-8")
    out = base / "built"
    written = site.build_site(DOCS, STATIC, MERMAID, str(out),
                              os.path.join(ROOT, "README.md"),
                              os.path.join(ROOT, "tdc-logo.png"), str(offline))
    return _Built(str(out), written)


# --- The addresses -----------------------------------------------------------


def test_page_url_names_the_folder_of_a_page():
    """One folder per page, and the guide's index is /guide/, not /readme/."""
    assert site.page_url("README.md") == "guide"
    assert site.page_url("web-ui.md") == "web-ui"
    assert site.page_url("troubleshooting.md") == "troubleshooting"
    # Every page of the guide has a folder, and no two share one - read off the
    # index, so a new page of the guide needs no number changed here
    order = site.page_order(_read("docs", "README.md"))
    folders = [site.page_url(name) for name in order]
    assert len(set(folders)) == len(order), folders
    assert "" not in folders
    # A floor, not a count: the guide has been a dozen pages and more since it
    # was written, and a page_order that suddenly reads two means the index was
    # not understood rather than that the guide shrank
    assert len(order) >= 12, \
        "page_order read %d pages out of docs/README.md: %s" % (len(order), order)


def test_site_links_point_at_the_other_pages_and_keep_their_anchors():
    link = site.site_link_target
    # A page of the guide is a folder next to this one, with its anchor kept
    assert link("web-ui.md", "rizin.md") == "../web-ui/"
    assert link("web-ui.md#charts", "rizin.md") == "../web-ui/#charts"
    assert link("README.md", "rizin.md") == "../guide/"
    assert link("README.md#detection-engines", "rizin.md") == "../guide/#detection-engines"
    # An anchor of this page stays an anchor: the pages are separate files, so
    # nothing has to say which page it belongs to
    assert link("#limits", "rizin.md") == "#limits"
    assert link("#ARM64 Hosts", "memory.md") == "#arm64-hosts"
    # The repository's README is the website's front page, not a file to fetch
    assert link("../README.md", "web-ui.md") == "../"
    assert link("../README.md#web-ui-tabs", "web-ui.md") == "../#web-ui-tabs"
    # ... and the front page's anchors are the ones this generator writes, so a
    # fragment meant for it is slugged like a heading
    assert link("../README.md#Web UI Tabs", "web-ui.md") == "../#web-ui-tabs"
    # A screenshot is shipped as a file next to the pages, whatever its
    # extension is written like - the picture and a link to it are one file
    assert link("../static/dashboard.png", "web-ui.md") == "../assets/img/dashboard.png"
    assert link("../static/WIDE.PNG", "web-ui.md") == "../assets/img/WIDE.PNG"
    # Any other file of the repository is read on github.com, with its fragment
    # as it stands: "#L10" is a line of that file, not a heading to slug
    assert link("../Vagrantfile.utm", "setup.md") == site.REPO_BLOB + "Vagrantfile.utm"
    assert link("../make.ps1#L10", "setup.md") == site.REPO_BLOB + "make.ps1#L10"
    # A relative path that is no page of the guide is a file of the repository
    # too: the site ships the pages, their pictures and the extras, nothing else
    assert link("superpowers/specs/x.md", "rizin.md") == site.REPO_BLOB + "docs/superpowers/specs/x.md"
    assert link("notes.txt", "rizin.md") == site.REPO_BLOB + "docs/notes.txt"
    # The page a link means, however it is written
    assert link("./rizin.md", "api.md") == "../rizin/"
    assert link("Rizin.MD#Sessions", "api.md") == "../rizin/#sessions"
    # The web is the web
    assert link("https://rizin.re", "rizin.md") == "https://rizin.re"
    assert link("http://localhost:9000/", "api.md") == "http://localhost:9000/"
    assert link("mailto:nobody@example.com", "api.md") == "mailto:nobody@example.com"
    # A scheme that could run code is refused, as in the wiki
    assert link("javascript:alert(1)", "rizin.md") is None
    assert link("JavaScript:alert(1)", "rizin.md") is None
    assert link("data:text/html,<script>", "rizin.md") is None
    # And so is a path from the server's root: the site lives under
    # /transportable-detonation-chamber/ and must open from a folder too
    assert link("/api/files", "api.md") is None


def test_a_site_link_is_relative_and_never_a_dead_md_path():
    """No link on the site keeps a .md path or starts at the server's root.

    The forms are not only the ones the docs write today: a path the generator
    does not recognise may not be handed on as it stands, or the reader gets a
    link to a file the site does not publish.
    """
    urls = ["web-ui.md", "web-ui.md#charts", "README.md", "README.md#detection-engines",
            "#limits", "../README.md", "../README.md#web-ui-tabs",
            "../static/dashboard.png", "../static/WIDE.PNG", "../Vagrantfile.utm",
            "./rizin.md", "rizin.md?plain=1", "superpowers/specs/x.md", "Rizin.MD",
            "sub/dir/x.md", "notes.txt", "https://rizin.re", "mailto:nobody@example.com"]
    for url in urls:
        target = site.site_link_target(url, "rizin.md")
        assert target is not None, url
        assert not target.startswith("/"), target
        # A scheme is not a path on this site: the web, where the file it names
        # is actually read, or a mail address
        if ":" in target.split("/")[0]:
            continue
        assert ".md" not in target.lower(), "%s -> %s" % (url, target)
        assert "static/" not in target, "%s -> %s" % (url, target)
        assert target.startswith(("../", "#")), "%s -> %s" % (url, target)


# --- The pictures ------------------------------------------------------------


def test_file_images_name_the_copied_files(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "dashboard.png").write_bytes(PNG)
    (static / "rizin.png").write_bytes(PNG)
    (static / "WIDE.PNG").write_bytes(PNG)
    (static / "demo.gif").write_bytes(b"GIF89a")
    (static / "notes.txt").write_text("not a picture", encoding="utf-8")
    images = site.file_images(str(static))
    assert images == {"dashboard.png": "../assets/img/dashboard.png",
                      "rizin.png": "../assets/img/rizin.png",
                      "WIDE.PNG": "../assets/img/WIDE.PNG"}
    # One picture, one answer: the <img> and a link to it name the same file
    for name, src in images.items():
        assert site.site_link_target("../static/" + name, "web-ui.md") == src
    # Same shape as the wiki's, so the renderer needs no second branch
    assert set(images) == set(site.embed_images(str(static)))
    assert site.file_images(str(tmp_path / "nowhere")) == {}


def test_file_images_names_only_files(tmp_path):
    """A directory named like a picture is not one: Task 2 copies every file
    this names, and a folder in the list would stop that copy."""
    static = tmp_path / "static"
    static.mkdir()
    (static / "dashboard.png").write_bytes(PNG)
    (static / "folder.png").mkdir()
    assert site.file_images(str(static)) == {
        "dashboard.png": "../assets/img/dashboard.png"}


def test_a_site_page_shows_its_pictures_as_files(tmp_path):
    """No `data:` URI on the website: every picture is loaded when it is needed."""
    static = tmp_path / "static"
    static.mkdir()
    (static / "shot.png").write_bytes(PNG)
    html = _site_html("# P\n\n![A shot](../static/shot.png)\n",
                      site.file_images(str(static)))
    assert '<img src="../assets/img/shot.png" alt="A shot" loading="lazy">' in html
    assert "data:" not in html
    # A picture that is not shipped is named, not shown as a broken frame
    missing = _site_html("# P\n\n![Gone](../static/gone.png)\n",
                         site.file_images(str(static)))
    assert '<span class="no-image">[gone.png: Gone]</span>' in missing


def test_a_site_page_says_nothing_about_a_network_it_has():
    """The wiki warns before a link the VM cannot follow. The website is in the
    network itself, so the same link stands there without a note."""
    text = "# P\n\nThe [Vagrantfile](../Vagrantfile.utm) is there.\n"
    assert site.NETWORK_NOTE in site.render_markdown(text, {}, page="setup.md")
    html = _site_html(text)
    assert site.NETWORK_NOTE not in html
    assert "net-note" not in html
    assert site.REPO_BLOB + "Vagrantfile.utm" in html
    # The note is asked for, not inferred from the link strategy: an output
    # with its own links that is read without a network still gets it
    noted = site.render_markdown(text, {}, page="setup.md",
                                 links=site.site_link_target, scoped=False)
    assert site.NETWORK_NOTE in noted


# --- The anchors -------------------------------------------------------------


def test_headings_are_unique_per_page_even_when_the_text_repeats():
    """A search hit must land on the section it was found in.

    Two headings with the same words are one id in the markdown's own rules, so
    the second one gets a counted id - and a reader following a hit to the
    first one is not dropped into the second.
    """
    text = ("# Rizin\n\n## Limits\n\nThe first.\n\n## Sessions\n\nMore.\n\n"
            "## Limits\n\nThe second.\n")
    html = _site_html(text)
    found = site.headings(html)
    assert found == [(1, "rizin", "Rizin"), (2, "limits", "Limits"),
                     (2, "sessions", "Sessions"), (2, "limits-2", "Limits")], found
    ids = [hid for _, hid, _ in found]
    assert len(set(ids)) == len(ids)
    # Deterministic: the same page rendered twice carries the same ids
    assert site.headings(_site_html(text)) == found
    # And the page's own links reach the ids the page carries
    linked = _site_html(text + "\nSee the [limits](#limits).\n")
    assert '<a href="#limits">limits</a>' in linked
    # A counted id may not be claimed by a heading that slugs to it on its own:
    # "Limits 2" IS "limits-2", so the count the repetition reached is not free
    # and the next one has to look further. Two elements with one id send an
    # in-page link and a search hit to whichever of them comes first.
    collide = ("# Rizin\n\n## Limits\n\nThe first.\n\n## Limits\n\nThe second.\n\n"
               "## Limits 2\n\nA section of its own.\n")
    ids = [hid for _, hid, _ in site.headings(_site_html(collide))]
    assert ids == ["rizin", "limits", "limits-2", "limits-2-2"], ids
    assert len(set(ids)) == len(ids), ids
    # ... and the other way round, where the repetition runs into it
    other_way = ("# Rizin\n\n## Limits 2\n\nA section of its own.\n\n"
                 "## Limits\n\nThe first.\n\n## Limits\n\nThe second.\n")
    ids = [hid for _, hid, _ in site.headings(_site_html(other_way))]
    assert ids == ["rizin", "limits-2", "limits", "limits-3"], ids
    assert len(set(ids)) == len(ids), ids
    # The wiki counts the same way, with its page in front of every id
    wiki_ids = [hid for _, hid, _ in
                site.headings(site.render_markdown(collide, {}, page="rizin.md"))]
    assert wiki_ids == ["rizin", "rizin--limits", "rizin--limits-2",
                        "rizin--limits-2-2"], wiki_ids


def test_an_anchor_of_the_site_is_the_one_github_makes():
    """The docs write their anchors by hand (`](#own-dashboards)`), so an
    anchor of a page is the heading's own slug - not the wiki's page--slug,
    which only exists because the wiki is one document."""
    text = "# Logs\n\n## Own Dashboards\n\nHow.\n\nSee the [way](#own-dashboards).\n"
    html = _site_html(text, page="logs.md")
    assert '<h2 id="own-dashboards">Own Dashboards</h2>' in html
    assert '<a href="#own-dashboards">way</a>' in html
    assert "logs--" not in html
    # The wiki keeps its prefix
    assert '<h2 id="logs--own-dashboards">Own Dashboards</h2>' \
        in site.render_markdown(text, {}, page="logs.md")


def test_a_heading_without_sluggable_words_still_carries_an_id():
    """An id is what a link and a search hit aim at: a heading of symbols alone
    (an emoji, a dash) may not end up with an empty one."""
    html = _site_html("# \u2b50\n\n## \u2b50\n\nText.\n", page="web-ui.md")
    ids = [hid for _, hid, _ in site.headings(html)]
    assert ids == ["web-ui", "web-ui-2"], ids


# --- The wiki, unmoved -------------------------------------------------------


def test_the_wiki_mode_is_untouched():
    """The defaults are today's behaviour, byte for byte.

    WIKI_HTML was taken from the generator before the website was taught: the
    offline wiki is the only documentation on a machine with no network, and
    1100 lines of tests in tests/test_wiki.py rest on this output.
    """
    assert site.render_markdown(WIKI_FIXTURE, WIKI_IMAGES, page="rizin.md") == WIKI_HTML
    # The same call written out with the new arguments at their defaults
    assert site.render_markdown(WIKI_FIXTURE, WIKI_IMAGES, page="rizin.md",
                                links=None, scoped=True, net_note=True) == WIKI_HTML
    # ... and the context the renderer builds for it
    ctx = site._Ctx(WIKI_IMAGES, "rizin.md")
    assert ctx.heading_id("Limits", 2) == "rizin--limits"
    assert ctx.heading_id("Limits", 2) == "rizin--limits-2"
    assert ctx.heading_id("Rizin", 1) == "rizin"


def test_the_two_outputs_render_the_real_pages_differently_but_both_whole():
    """Every page of the guide, in both shapes: the same headings, the wiki's
    anchors prefixed and the website's not, every link relative or on the web,
    and no `data:` picture on the website."""
    order = site.page_order(_read("docs", "README.md"))
    images = site.file_images(os.path.join(ROOT, "static"))
    for name in order:
        text = _read("docs", name)
        wiki_html = site.render_markdown(text, {}, page=name)
        page_html = _site_html(text, images, page=name)
        wiki_heads = [(level, head) for level, _, head in site.headings(wiki_html)]
        page_heads = [(level, head) for level, _, head in site.headings(page_html)]
        assert wiki_heads == page_heads, name
        ids = [hid for _, hid, _ in site.headings(page_html)]
        assert len(set(ids)) == len(ids), name
        assert all(not hid.startswith(site.page_url(name) + "--") for hid in ids), name
        for url in re.findall(r'(?:href|src)="([^"]*)"', page_html):
            assert not url.startswith("/"), "%s: %s" % (name, url)
            assert not url.startswith("data:"), "%s: %s" % (name, url)
            if not url.startswith("http"):
                assert ".md" not in url, "%s: %s" % (name, url)
                assert "../static/" not in url, "%s: %s" % (name, url)


# --- The front page's own links ----------------------------------------------


def test_home_links_stay_inside_the_site():
    """The front page is the site's root, so its links carry no "../".

    site_link_target is the strategy of a page inside /x/; the README writes
    its links from the repository's root (`docs/setup.md`, `static/x.png`,
    `tdc-logo.png`), and a "../" from the root would leave the published site
    altogether (Review Focus 5).
    """
    link = site.home_link_target
    assert link("docs/setup.md", "README.md") == "setup/"
    assert link("docs/web-ui.md#charts", "README.md") == "web-ui/#charts"
    assert link("docs/README.md", "README.md") == "guide/"
    assert link("docs/README.md#detection-engines", "README.md") == "guide/#detection-engines"
    # Its own anchors stay anchors, slugged the way the headings are
    assert link("#quick-start", "README.md") == "#quick-start"
    assert link("#Quick Start", "README.md") == "#quick-start"
    # The shipped extras
    assert link("static/dashboard.png", "README.md") == "assets/img/dashboard.png"
    assert link("static/demo.gif", "README.md") == "assets/demo.gif"
    assert link("tdc-logo.png", "README.md") == "assets/tdc-logo.png"
    # Any other file of the repository is read on github.com, fragment as it is
    assert link("Vagrantfile.utm", "README.md") == site.REPO_BLOB + "Vagrantfile.utm"
    assert link("make.ps1#L10", "README.md") == site.REPO_BLOB + "make.ps1#L10"
    # A paper the site never publishes is a file of the repository too
    assert link("docs/superpowers/specs/x.md", "README.md") == \
        site.REPO_BLOB + "docs/superpowers/specs/x.md"
    # The web, and what is refused
    assert link("https://rizin.re", "README.md") == "https://rizin.re"
    assert link("mailto:nobody@example.com", "README.md") == "mailto:nobody@example.com"
    assert link("javascript:alert(1)", "README.md") is None
    assert link("/api/files", "README.md") is None
    # Nothing climbs out of the site, and no .md path survives
    for url in ["docs/setup.md", "docs/README.md#x", "#quick-start", "static/a.png",
                "tdc-logo.png", "Vagrantfile.utm", "docs/superpowers/x.md", "a/b/c.txt"]:
        target = site.home_link_target(url, "README.md")
        assert not target.startswith(("/", "../")), "%s -> %s" % (url, target)
        if ":" not in target.split("/")[0]:
            assert ".md" not in target.lower(), "%s -> %s" % (url, target)


def test_home_images_name_the_files_as_the_front_page_reads_them(tmp_path):
    """The same pictures, one folder level up from a page of the guide."""
    static = tmp_path / "static"
    static.mkdir()
    (static / "dashboard.png").write_bytes(PNG)
    assert site.home_images(str(static)) == {"dashboard.png": "assets/img/dashboard.png"}
    assert set(site.home_images(str(static))) == set(site.file_images(str(static)))


# --- The front page itself ---------------------------------------------------
#
# The front page is the repository's README, whole and in order. Three things
# about it are not markdown: the centred raw HTML of its hero and its feature
# pictures, the badges (images of a third-party service), and links written
# from the root of the repository. What is held here is that all three arrive
# as a page - and that nothing else of the raw HTML does.


README = _read("README.md")

# The pages the repository's README links. A fixture that hands the real README
# to a small guide has to publish them too: the build refuses a link to a
# folder it does not write, which is the gate of
# test_the_build_refuses_a_page_the_index_forgot_and_a_link_to_nowhere doing
# its work rather than a fixture being awkward.
README_PAGES = dict(
    (name, "# %s\n\nA page of the fixture guide.\n" % name[:-3])
    for name in sorted(set(re.findall(r"\(docs/([a-z0-9_-]+\.md)", README)))
    if name != "README.md")


def _front_page(text=None, images=None):
    """The README as the front page renders it (the real pictures by default)."""
    return site.readme_html(README if text is None else text,
                            site.home_images(STATIC) if images is None else images,
                            site.SITE_LOGO)


def _markdown_headings(text):
    """(level, text) of every heading of a markdown file, fences skipped.

    A `#` inside a fenced block is a shell comment, not a heading, and the
    README's Quick Start is full of them.
    """
    found = []
    fence = None
    for line in text.replace("\r\n", "\n").split("\n"):
        hit = re.match(r"^(\s{0,3})(`{3,})\s*([\w+.-]*)\s*$", line)
        if hit:
            if fence is None:
                fence = len(hit.group(2))
            elif len(hit.group(2)) >= fence and not hit.group(3):
                fence = None
            continue
        if fence is not None:
            continue
        head = re.match(r"^(#{1,6})\s+(.*?)\s*$", line)
        if head:
            found.append((len(head.group(1)), head.group(2)))
    return found


def _readme_features(text):
    """The feature blocks of the README's own section: name, picture, sentence.

    The pattern the spec names - a bold name with a sentence, then a centred
    picture - read out of the README itself, so a feature renamed or added
    there is renamed or added here too. A list of ten in this file would pass
    while the page went stale.
    """
    section = text[text.index("## What it does"):]
    end = section.find("\n## ", 1)
    if end > 0:
        section = section[:end]
    found = []
    for m in re.finditer(r'^\*\*(.+?)\*\*(.*?)\n\n<p align="center">\s*'
                         r'<img src="static/([^"]+)"', section, re.S | re.M):
        found.append((m.group(1), m.group(3), m.group(2)))
    return found


def test_the_landing_page_is_the_whole_readme(real_site, tmp_path):
    """Every heading of README.md is on `/`, Credits and License included.

    The spec's decision: the front page is the rendered README, with no
    section picked, reordered or dropped. That is what keeps the README's own
    jump targets alive, keeps the two pictures only it uses in use, and puts
    Credits and License on the one public page they belong on - and it only
    holds if the page really is the whole file.
    """
    html = real_site.read("index.html")
    found = site.headings(html)
    assert found, "the front page carries no heading at all"
    for level, text in _markdown_headings(README):
        assert (level, text) in [(lvl, txt) for lvl, _, txt in found], \
            "README.md has %s%s, the front page does not" % ("#" * level, text)
    # The sections that exist nowhere else on the site
    for name in ("Credits", "License", "Security Notes", "Platform support"):
        assert name in [txt for _, _, txt in found], name
    assert "GPL-3.0" in html and "LGPL-3.0" in html, "the licences of Credits"
    # The README's own jump targets, which it and the guide link by name
    ids = [hid for _, hid, _ in found]
    for anchor in ("quick-start", "what-it-does", "web-ui-tabs", "credits"):
        assert anchor in ids, anchor
    # The two pictures only the README uses stay in use
    for picture in ("theme_telemetry.png", "wiki.png"):
        assert "assets/img/%s" % picture in html, picture
    # ... and a section added to the README is on the page without a line
    # changing in the generator
    grown = README + "\n## Afterword\n\nA section nobody selected.\n"
    built = _fixture_site(tmp_path, dict(README_PAGES, **{"only.md": "# Only\n\nA page.\n"}),
                          images=tuple(site.file_images(STATIC)), readme=grown)
    front = built.read("index.html")
    assert ">Afterword</h2>" in front
    assert "A section nobody selected." in front
    assert ">Credits</h2>" in front, "the rest of the README is still there"


def test_the_hero_carries_logo_title_and_the_one_sentence():
    """The centred HTML of the top of the README becomes the hero.

    `<p align="center"><img src="tdc-logo.png">`, `<h1 align="center">` and the
    one bold sentence are raw HTML, which the parser escapes to text
    everywhere else. On the front page they are the page's own head.
    """
    html = _front_page()
    assert '<header class="hero">' in html, "no hero on the front page"
    hero = html[html.index('<header class="hero">'):html.index("</header>")]
    # The logo lies in the repository's root, not in static/, and is shipped
    assert '<img src="assets/tdc-logo.png"' in hero, hero[:400]
    assert 'alt="Transportable Detonation Chamber"' in hero
    # The title, as a heading of the page and not as text
    assert re.search(r'<h1 id="[^"]+"[^>]*>Transportable Detonation Chamber</h1>',
                     hero), hero[:600]
    assert (1, site.slug(site.TITLE), site.TITLE) in site.headings(html)
    # The one sentence, read out of the README
    sentence = re.search(r"<strong>(.+?)</strong>", README, re.S).group(1).strip()
    assert sentence.startswith("A pre-configured Windows 11 VM"), sentence
    assert "<strong>%s</strong>" % site.esc(sentence) in hero, sentence
    # Nothing of those blocks is escaped text any more
    assert "&lt;p align=" not in html and "&lt;h1 align=" not in html
    assert 'align="center"' not in html


def test_the_badges_become_buttons_without_a_request_to_the_outside():
    """The badges are images of a third party: the links stay, the images go.

    A page that loads img.shields.io asks a foreign server for twelve pictures
    every time a reader opens it, which the constraints rule out. The labels
    and the jump targets are the information; the pictures are not.
    """
    html = _front_page()
    assert "shields.io" not in html and "shields" not in html
    assert not re.search(r'src="https?:', html), "a picture from the web"
    # Every badge that carried a link keeps it, as a labelled chip
    linked = re.findall(r'<a href="([^"]+)"><img src="https://img\.shields\.io'
                        r'[^"]*" alt="([^"]*)">\s*</a>', README)
    # The README's own badges, read rather than counted: one more badge there is
    # one more chip here, and the floor says the reading still works
    assert len(linked) >= 3, \
        "only %d linked badges were read out of the README's head: %s" % (
            len(linked), linked)
    assert len(linked) == len(re.findall(r'<a href="[^"]+"><img src="https://img',
                                         README)), linked
    assert html.count('<a class="chip" href=') == len(linked), \
        "%d chips for %d linked badges" % (
            html.count('<a class="chip" href='), len(linked))
    for url, label in linked:
        target = site.home_link_target(url, "README.md")
        assert '<a class="chip" href="%s">%s</a>' % (site.esc(target), site.esc(label)) \
            in html, "%s -> %s" % (label, target)
    # ... and a badge that is only a statement keeps its label
    for label in ("Windows 11", "macOS ARM64", "Hyper-V", "QEMU", "Python 3.12",
                  ".NET 8", "Rust"):
        assert '<span class="chip">%s</span>' % label in html, label
    # The five links of the first row are the README's own jump targets, two
    # pages of the guide and the published site, and they survive as such
    assert '<a class="chip" href="#quick-start">Quick Start</a>' in html
    assert '<a class="chip" href="web-ui/">Demo</a>' in html
    assert '<a class="chip" href="%s">Documentation</a>' % SITE_URL in html


def test_the_ten_features_become_cards_with_their_picture():
    """One card per feature block of "## What it does": name, sentence, picture.

    The card look is presentation, not selection: the generator recognises the
    pattern, so the cards are the README's feature blocks in their order, each
    with the screenshot that stands under it - ten of them today, and an
    eleventh feature in the README is an eleventh card by itself.
    """
    features = _readme_features(README)
    assert len(features) >= 8, \
        "the README's showcase is down to %d feature blocks (%s): either the " \
        "section was rewritten or the pattern is no longer recognised" % (
            len(features), [name for name, _, _ in features])
    html = _front_page()
    assert site.HOME_FEATURES in [hid for _, hid, _ in site.headings(html)], \
        "the generator looks for the section #%s; the README no longer has it" \
        % site.HOME_FEATURES
    cards = re.findall(r'<article class="card">(.*?)</article>', html, re.S)
    assert len(cards) == len(features), "%d cards for %d features" % (
        len(cards), len(features))
    for card, (name, picture, sentence) in zip(cards, features):
        assert '<img src="assets/img/%s"' % picture in card, name
        assert '<h3 id="%s">%s</h3>' % (site.slug(name), site.esc(name)) in card, name
        # The sentence under the name, not only the name
        first = site.esc(sentence.strip().lstrip("\u2014- ").split("\n")[0])
        assert first[:40] in card, "%s: %s" % (name, first[:40])
        # A card is a place a link can aim at, and headings() reports it
        assert (3, site.slug(name), name) in site.headings(html), name
    # The cards stand in one grid, in the section that holds them
    assert html.count('<div class="cards">') == 1
    grid = html.index('<div class="cards">')
    assert grid > html.index('id="%s"' % site.HOME_FEATURES)
    assert html[grid:].count('<article class="card">') == len(features)
    # ... and the whole grid stands inside that section: it opens after its own
    # heading and closes before the next one. A grid flushed at the end of the
    # document instead would still be "after what-it-does".
    following = re.search(r'<h2 id="([^"]+)"', html[grid:])
    assert following, "no section follows the cards"
    assert following.group(1) == "architecture", following.group(1)
    assert html.index("</div>", grid) < grid + following.start(), \
        "the grid reaches past the end of its own section"
    # Renaming a feature in the README renames the card (both are read here)
    renamed = README.replace("**Detonation with a verdict**",
                             "**Detonation with a judgement**", 1)
    assert renamed != README
    grown = _front_page(renamed)
    assert '>Detonation with a judgement</h3>' in grown
    assert "Detonation with a verdict" not in grown


def test_an_eleventh_feature_becomes_an_eleventh_card(tmp_path):
    """The pattern, not a fixed list of ten.

    A feature added to the README is a card on the front page with nothing
    changed here: that is the difference between recognising the shape of a
    feature block and carrying a list of the ten there are today.
    """
    eleventh = (
        "**An eleventh feature** - the README grew one, with its own picture\n"
        "and a link into the guide ([Setup](docs/setup.md)).\n"
        "\n"
        '<p align="center">\n'
        '  <img src="static/eleventh.png" alt="A shot of the eleventh" width="88%">\n'
        "</p>\n")
    grown = README.replace("\n---\n\n## Architecture",
                           "\n" + eleventh + "\n---\n\n## Architecture", 1)
    assert grown != README, "the section's end moved"
    # One more than the README has, whatever that is today: main added an
    # eleventh feature while this was being built, and a hard number would
    # only fail again with the twelfth.
    assert len(_readme_features(grown)) == len(_readme_features(README)) + 1
    built = _fixture_site(tmp_path, dict(README_PAGES, **{"only.md": "# Only\n\nA page.\n"}),
                          images=tuple(site.file_images(STATIC)) + ("eleventh.png",),
                          readme=grown)
    html = built.read("index.html")
    cards = re.findall(r'<article class="card">(.*?)</article>', html, re.S)
    grown_count = len(_readme_features(grown))
    assert len(cards) == grown_count, len(cards)
    assert '<h3 id="an-eleventh-feature">An eleventh feature</h3>' \
        in cards[-1], cards[-1]
    assert '<img src="assets/img/eleventh.png"' in cards[-1]
    assert "assets/img/eleventh.png" in built.written
    # The ones before it are untouched, and all of them are in the one grid
    assert '<img src="assets/img/detonation_results.png"' in cards[0]
    assert html.count('<div class="cards">') == 1


def test_only_the_two_centred_forms_become_html_on_the_front_page():
    """Two raw forms are understood; every other raw line stays text.

    The front page is the one page of the site that lets raw HTML through, so
    what it lets through has to be exactly two shapes. An `onerror=`, a
    `<script>`, another tag or another alignment is text here as it is
    everywhere else - the README is a source, not a template.
    """
    text = (
        '<p align="center">\n  <img src="static/shot.png" alt="A shot">\n</p>\n'
        "\n"
        '<p align="center">\n  <strong>One sentence.</strong>\n</p>\n'
        "\n"
        '<p align="center"><img src="shot.png" onerror="alert(1)"></p>\n'
        "\n"
        '<p align="center"><script>alert(2)</script></p>\n'
        "\n"
        '<div align="center">A div.</div>\n'
        "\n"
        '<p align="left">Not centred.</p>\n'
        "\n"
        '<p align="center"><a href="javascript:alert(3)">click</a></p>\n'
        "\n"
        '<p align="center"><iframe src="https://e.test/x"></iframe></p>\n'
        "\n"
        '<p align="center"><img src="shot.png" alt="Crossed"><em>a</em></strong></p>\n'
        "\n"
        '<p align="center"><script>alert(4)</script><b>x</b></p>\n')
    html = site.readme_html(text, {"shot.png": "assets/img/shot.png"}, site.SITE_LOGO)
    # The two forms arrive as a page
    assert '<img src="assets/img/shot.png" alt="A shot" loading="lazy">' in html
    assert "<strong>One sentence.</strong>" in html
    # Everything else is text, as the parser makes it
    for dead in ("<script", "<iframe", "<div", 'onerror="', 'href="javascript',
                 "<p align"):
        assert dead not in html, dead
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "&lt;div align=&quot;center&quot;&gt;A div." in html
    assert "&lt;p align=&quot;left&quot;&gt;Not centred." in html
    assert "onerror=&quot;alert(1)&quot;" in html, "the stray picture is shown as it is"
    assert "javascript:alert(3)" in html, "a refused link stays visible as text"
    assert "&lt;/strong&gt;" in html, "crossed marks are not a form of ours"
    # A tag this output does not know is text wherever it stands in the block,
    # not only at its end: here it stands before a mark that is understood.
    assert "&lt;script&gt;alert(4)&lt;/script&gt;" in html, html
    assert "<b>x</b>" not in html, html
    # A block that is not understood does not become a centred line with its
    # content escaped: it is not taken out of the markdown at all. Only the two
    # recognised blocks above are the page's own elements.
    assert html.count('class="centred"') == 1, html
    assert html.count('class="shot"') == 1, html


def test_a_centred_block_inside_a_code_fence_stays_in_the_fence():
    """A code example that shows the markup is an example, not markup.

    The README may one day write its own centred HTML inside a ``` block (the
    badge of the published site is the next thing to be documented). Lifting
    that out would both break the code block around it and let raw HTML out of
    the one place where every page shows text as it stands.
    """
    text = ("A sample:\n"
            "\n"
            "```html\n"
            '<p align="center">\n'
            "  <strong>In a code block.</strong>\n"
            "</p>\n"
            "```\n"
            "\n"
            "Done.\n")
    html = site.readme_html(text, {}, site.SITE_LOGO)
    assert "<strong>In a code block.</strong>" not in html
    assert "&lt;p align=&quot;center&quot;&gt;" in html, html
    assert "&lt;strong&gt;In a code block.&lt;/strong&gt;" in html
    # ... and the block around it is still one code block
    assert html.count('<pre class="code">') == 1, html
    assert html.endswith("<p>Done.</p>"), html[-120:]


def test_a_centred_picture_carries_its_caption_and_a_centred_title_its_id():
    """The two forms in their full shape: a captioned picture, a centred line.

    The README writes its screenshots with a `<br><sub>` caption under them
    and its title as a centred `<h1>`; the caption is the picture's and the
    title is a heading of the page, with an id a link can aim at.
    """
    text = ('<h1 align="center">The Title</h1>\n'
            "\n"
            '<p align="center">\n'
            '  <img src="static/shot.png" alt="A shot" width="90%">\n'
            '  <br><sub>What it shows &mdash; in a caption, with '
            '<a href="docs/setup.md">a link</a></sub>\n'
            "</p>\n"
            "\n"
            '<p align="center">\n  <em>A tagline &bull; and another</em>\n</p>\n')
    html = site.readme_html(text, {"shot.png": "assets/img/shot.png"}, site.SITE_LOGO)
    assert '<h1 id="the-title">The Title</h1>' in html
    assert '<figure class="shot"><img src="assets/img/shot.png" alt="A shot" ' \
        'loading="lazy">' in html, html
    assert '<figcaption>What it shows \u2014 in a caption, with ' \
        '<a href="setup/">a link</a></figcaption>' in html, html
    assert '<p class="centred"><em>A tagline \u2022 and another</em></p>' in html


def test_nothing_after_a_centred_block_is_dropped():
    """Text that shares the closing tag's line is text, not a lost sentence.

    The block is taken by whole lines, so anything standing after `</p>` would
    go into the block with it and never be seen. The front page is the whole
    README: a sentence may not vanish, so such a block is not one of ours and
    its lines stay in the markdown.
    """
    for text in ('<p align="center">A line.</p> and a trailing sentence.\n',
                 '<p align="center">\n  <strong>A line.</strong>\n'
                 '</p> and a trailing sentence.\n'):
        html = site.readme_html(text, {}, site.SITE_LOGO)
        assert "and a trailing sentence." in html, html
        assert 'class="centred"' not in html, html
        assert "&lt;p align=&quot;center&quot;&gt;" in html, html
    # Whitespace after the closing tag is not a sentence: that block is ours
    html = site.readme_html('<p align="center">A line.</p>   \n', {}, site.SITE_LOGO)
    assert html == '<header class="hero"><p class="centred">A line.</p></header>', html


def test_a_centred_block_that_breaks_its_own_markup_stays_text():
    """A block understood by halves is not understood: it stays text.

    An attribute that is not quoted, a mark that is never closed, a link that
    is never closed - each would otherwise leak into the rest of the page
    (`<strong>` left open makes everything below it bold) or silently drop
    what it could not read.
    """
    cases = [
        # an attribute with no quotes: read as a picture, the rest ignored
        '<p align="center"><img src="static/shot.png" width=90%></p>',
        # a mark that is never closed
        '<p align="center"><strong>Unclosed</p>',
        # a link that is never closed
        '<p align="center"><a href="docs/setup.md">Setup</p>',
        # a mark closed in the wrong order
        '<p align="center"><strong><em>Crossed</strong></em></p>',
    ]
    for case in cases:
        html = site.readme_html(case + "\n\nA paragraph after it.\n",
                                {"shot.png": "assets/img/shot.png"}, site.SITE_LOGO)
        assert 'class="centred"' not in html, case
        assert 'class="shot"' not in html, case
        assert "<strong>" not in html and "<em>" not in html, case
        assert '<img src="assets/img/shot.png"' not in html, case
        assert '<a href="setup/"' not in html, case
        assert "&lt;p align=&quot;center&quot;&gt;" in html, case
        # and the page after it is untouched
        assert "<p>A paragraph after it.</p>" in html, case


def test_a_feature_without_a_picture_is_no_card():
    """A card needs the picture the README puts under the feature.

    Without that precondition the next block of the document - a centred line,
    a badge row - would be formatted into the card's picture slot.
    """
    text = ("## What it does\n"
            "\n"
            "**A feature** - with a sentence and no picture at all.\n"
            "\n"
            '<p align="center">\n  <em>A tagline, not a screenshot.</em>\n</p>\n')
    html = site.readme_html(text, {"shot.png": "assets/img/shot.png"}, site.SITE_LOGO)
    assert '<article class="card">' not in html, html
    assert '<div class="cards">' not in html, html
    assert "<strong>A feature</strong> - with a sentence" in html, html
    assert '<p class="centred"><em>A tagline, not a screenshot.</em></p>' in html, html


def test_a_heading_in_a_code_fence_does_not_end_the_feature_section():
    """A `#` line inside a fence is a comment, not the next section.

    The README's own Quick Start is full of them; one inside the feature
    section would otherwise end it and the features under it would quietly
    stop being cards.
    """
    text = ("## What it does\n"
            "\n"
            "**One** - the first feature.\n"
            "\n"
            '<p align="center">\n  <img src="static/shot.png" alt="one">\n</p>\n'
            "\n"
            "```bash\n"
            "## not a heading, a comment\n"
            "make run\n"
            "```\n"
            "\n"
            "**Two** - the second feature.\n"
            "\n"
            '<p align="center">\n  <img src="static/shot.png" alt="two">\n</p>\n')
    html = site.readme_html(text, {"shot.png": "assets/img/shot.png"}, site.SITE_LOGO)
    cards = re.findall(r'<article class="card">(.*?)</article>', html, re.S)
    assert len(cards) == 2, html
    assert '<h3 id="one">One</h3>' in cards[0] and '<h3 id="two">Two</h3>' in cards[1]
    # The fence is still a code block, and its comment is text in it
    assert "&#x27;" not in html  # nothing odd got quoted into it
    assert "## not a heading, a comment" in html
    # Two grids, because the fence stands between the two features
    assert html.count('<div class="cards">') == 2, html


def test_a_centred_title_without_words_still_gets_the_products_id():
    """A title that is only a picture may not take the guide's own name.

    The render context falls back to the page's folder for a heading that
    slugs to nothing, and the front page's folder name is "guide" - which is
    the address of the guide's index. The product's name is the honest answer
    for the front page's own title.
    """
    text = ('<h1 align="center"><img src="tdc-logo.png" alt=""></h1>\n')
    html = site.readme_html(text, {}, "assets/tdc-logo.png")
    assert 'id="guide"' not in html, html
    assert 'id="%s"' % site.slug(site.TITLE) in html, html
    assert (1, site.slug(site.TITLE)) in [(lvl, hid)
                                          for lvl, hid, _ in site.headings(html)]


def test_a_renamed_feature_section_stops_the_build(tmp_path):
    """A README that lost the section the cards come from stops the build.

    The suite says so loudly, but a build that stayed silent would publish a
    front page without its showcase - the ten features as loose paragraphs
    with their screenshots between them. The generator and the README live in
    one repository, so a rename there is a build error here.
    """
    renamed = README.replace("## What it does", "## What it can do", 1)
    assert renamed != README
    with pytest.raises(site.WikiError) as err:
        site.readme_html(renamed, site.home_images(STATIC), site.SITE_LOGO)
    message = str(err.value)
    assert site.HOME_FEATURES in message and "HOME_FEATURES" in message, message
    assert str(len(_readme_features(README))) in message, message
    # The build stops before it writes anything
    with pytest.raises(site.WikiError):
        _fixture_site(tmp_path, dict(README_PAGES, **{"only.md": "# Only\n\nA page.\n"}),
                      images=tuple(site.file_images(STATIC)), readme=renamed)
    assert not os.path.isdir(str(tmp_path / "site")), "a refused build wrote a folder"
    # A README with no feature blocks at all is not a lost showcase
    assert site.readme_html("# Plain\n\nNo features here.\n", {}, site.SITE_LOGO)


# --- The build folder --------------------------------------------------------


def test_the_site_has_one_folder_per_page(real_site):
    """One address per page of the index, plus the front page.

    One folder with an index.html each, so /rizin/ is an address a reader can
    bookmark - and nothing out of docs/superpowers/, which holds German drafts
    and plans that are not published.
    """
    order = site.page_order(_read("docs", "README.md"))
    want = ["index.html"] + ["%s/index.html" % site.page_url(name) for name in order]
    assert want[1] == "guide/index.html"
    assert real_site.pages() == sorted(want), real_site.pages()
    # The front page and one page per entry of the index: nothing more, nothing
    # less. The number itself is the guide's business, not this test's.
    assert len(real_site.pages()) == len(order) + 1, real_site.pages()
    for rel in want:
        assert os.path.isfile(os.path.join(real_site.dir, rel)), rel
    # The shipped extras, and the download the header promises
    for extra in (".nojekyll", "assets/style.css", "assets/site.js",
                  "assets/mermaid.min.js", "assets/tdc-logo.png", "assets/demo.gif",
                  "assets/img/dashboard.png", "wiki.html"):
        assert extra in real_site.written, extra
        assert os.path.isfile(os.path.join(real_site.dir, extra)), extra
    # Every screenshot of static/ is shipped, under its own name
    for name in site.file_images(STATIC):
        assert "assets/img/%s" % name in real_site.written, name
    # Nothing of the internal papers
    assert os.path.isdir(os.path.join(DOCS, "superpowers")), "the papers moved"
    for rel in real_site.written:
        assert "superpowers" not in rel, rel
    # Every page says what it is, and the product's name stands there once
    for rel in real_site.pages():
        found = re.search(r"<title>(.*?)</title>", real_site.read(rel))
        assert found, rel
        assert found.group(1).count(site.TITLE) == 1, "%s: %s" % (rel, found.group(1))
    # ... and every page lets a keyboard past the header in one key: the first
    # focusable thing on it jumps to the content, and the target is there
    for rel in real_site.pages():
        html = real_site.read(rel)
        skip = re.search(r'<a class="skip" href="#([^"]+)">([^<]+)</a>', html)
        assert skip, "%s has no skip link" % rel
        assert html.index(skip.group(0)) < html.index('<header'), \
            "%s: the skip link is not the first thing on the page" % rel
        assert skip.group(2).strip(), rel
        assert ' id="%s"' % skip.group(1) in html, \
            "%s: the skip link aims at #%s, which is not on the page" % (
                rel, skip.group(1))


def test_every_docs_page_has_an_address(real_site):
    """A page the index forgets is a page the website loses (Review Focus 1).

    page_order reads docs/README.md only: a new page that nobody links from the
    index would be rendered into the wiki but have no address at all here. So
    the two sides are held against each other - the markdown that lies in
    docs/ and the order the index gives - instead of against a number.
    """
    names = sorted(name for name in os.listdir(DOCS) if name.lower().endswith(".md"))
    order = site.page_order(_read("docs", "README.md"))
    # The index and the folder say the same thing: every markdown of docs/ is
    # a page of the index (whose own first entry is docs/README.md, the
    # register), and every entry of the index is a file that is there
    assert sorted(order) == names, \
        "docs/ holds %s; the index orders %s" % (names, sorted(order))
    assert len(names) >= 12, \
        "the guide is the index and its pages; docs/ holds %d .md files: %s" % (
            len(names), names)
    for name in names:
        rel = "%s/index.html" % site.page_url(name)
        assert rel in real_site.written, \
            "docs/%s has no address: docs/README.md does not link it" % name
        # ... and the page is really that page, not an empty shell
        first = _read("docs", name).splitlines()[0].lstrip("# ").strip()
        assert site.esc(first) in real_site.read(rel), name


def test_every_relative_link_resolves_inside_the_build(real_site):
    """Every link of the site reaches a file the build wrote (Review Focus 5).

    The site is published under /transportable-detonation-chamber/ and has to
    open from a local folder too: a link that starts at the server's root or
    climbs above the build folder is dead in both places, and a jump target
    that no page carries drops the reader at the top of a page.
    """
    ids = {}
    for rel in real_site.pages():
        ids[rel] = set(re.findall(r'\bid="([^"]+)"', real_site.read(rel)))
    checked = 0
    for rel in real_site.pages():
        html = real_site.read(rel)
        folder = os.path.dirname(rel)
        for url in re.findall(r'(?:href|src)="([^"]*)"', html):
            if url.startswith(("http://", "https://", "mailto:", "data:")):
                continue  # the web, a mail address, or the document itself
            assert url, "%s: an empty link" % rel
            assert not url.startswith("/"), "%s: %s" % (rel, url)
            path, _, anchor = url.partition("#")
            if path:
                target = os.path.normpath(os.path.join(folder, path))
                assert not target.startswith(".."), \
                    "%s: %s climbs out of the site" % (rel, url)
                full = os.path.join(real_site.dir, target)
                if path.endswith("/") or os.path.isdir(full):
                    target = os.path.normpath(os.path.join(target, "index.html"))
                    full = os.path.join(real_site.dir, target)
                assert os.path.isfile(full), "%s: %s" % (rel, url)
            else:
                target = rel
            if anchor:
                page = target.replace(os.sep, "/")
                assert page in ids, "%s: %s" % (rel, url)
                assert anchor in ids[page], \
                    "%s: %s names a heading %s does not carry" % (rel, url, page)
            checked += 1
    assert checked > 200, "too few links checked: %d" % checked


def test_a_missing_picture_stops_the_build(tmp_path):
    """A picture static/ does not have is a 404 on a published page.

    The wiki draws a placeholder instead, which is honest in one file that
    carries its images; on the website the frame would be broken for every
    reader. The build says which page wants which file and writes nothing
    (Review Focus 4).
    """
    with pytest.raises(site.WikiError) as caught:
        _fixture_site(tmp_path, {"rizin.md": "# Rizin\n\n![Gone](../static/nope.png)\n"})
    message = str(caught.value)
    assert "rizin.md" in message and "nope.png" in message, message
    assert "static" in message, message
    out = tmp_path / "site"
    assert not out.exists() or not list(out.iterdir()), "a half-built site was left behind"
    # A link to a picture that is not shipped is the same dead end
    with pytest.raises(site.WikiError) as caught:
        _fixture_site(tmp_path, {"rizin.md": "# Rizin\n\n[a shot](../static/nope.png)\n"})
    assert "nope.png" in str(caught.value)
    assert not out.exists() or not list(out.iterdir())
    # A picture from somewhere else is not a file the site ships: it is named
    # in the page, as in the wiki, and stops nothing
    built = _fixture_site(tmp_path, {"rizin.md": "# Rizin\n\n![Far](https://e.test/a.png)\n"})
    assert 'class="no-image"' in built.read("rizin/index.html")
    # The picture that is there builds, the same page otherwise
    built = _fixture_site(tmp_path, {"rizin.md": "# Rizin\n\n![Here](../static/shot.png)\n"})
    assert '<img src="../assets/img/shot.png"' in built.read("rizin/index.html")


def _pages_with_a_mermaid_block():
    """The addresses whose markdown opens a ```mermaid fence.

    Read off the sources, not listed here: a new page with a diagram has to
    take the bundle with it, and a page that loses its diagram has to drop it.
    The front page is the repository's README, so it is read too. Fences are
    tracked open and closed, so a ```mermaid *inside* a code block - which the
    guide writes when it explains the generator - is not mistaken for one.
    """
    order = site.page_order(_read("docs", "README.md"))
    sources = [("index.html", _read("README.md"))]
    sources += [("%s/index.html" % site.page_url(name), _read("docs", name))
                for name in order]
    drawn = []
    for rel, text in sources:
        fence, found = None, False
        for line in text.splitlines():
            mark = re.match(r"^\s*(```+|~~~+)\s*(\S*)", line)
            if not mark:
                continue
            if fence is None:
                fence = mark.group(1)[:3]
                if mark.group(2).lower() == "mermaid":
                    found = True
            elif mark.group(1).startswith(fence) and not mark.group(2):
                fence = None
        if found:
            drawn.append(rel)
    return sorted(drawn)


def test_mermaid_rides_only_on_the_pages_with_a_diagram(real_site):
    """The bundle is 2.5 MB: a page without a diagram does not load it.

    It is the pinned copy from the repository, served from the site itself -
    not a CDN, which would be a third party at every page view and a version
    that can change under the hand.
    """
    with_diagram = sorted(rel for rel in real_site.pages()
                          if '<pre class="mermaid"' in real_site.read(rel))
    # Which pages carry a diagram is the markdown's business: the written
    # pages and their sources have to agree about it, both ways
    assert with_diagram == _pages_with_a_mermaid_block(), with_diagram
    for rel in real_site.pages():
        html = real_site.read(rel)
        drawn = "assets/mermaid.min.js" in html
        assert drawn == (rel in with_diagram), rel
        if drawn:
            assert "mermaid.initialize" in html, rel
            assert site.MERMAID_VERSION in html, rel
    # A floor on each side, so that neither branch of the rule above is
    # untested by accident: some page draws, and some page does not
    assert with_diagram, \
        "no page of the site carries a diagram, so 'only where needed' holds vacuously"
    assert len(real_site.pages()) > len(with_diagram), \
        "every page carries a diagram, so the bundle is never left off"
    # Written once, and it is the version this generator was written against
    assert [rel for rel in real_site.written if rel.endswith("mermaid.min.js")] == \
        ["assets/mermaid.min.js"]
    with open(os.path.join(real_site.dir, "assets", "mermaid.min.js"), "rb") as fh:
        bundle = fh.read()
    assert hashlib.sha256(bundle).hexdigest() == site.MERMAID_SHA256


def test_the_register_marks_the_current_page_and_prev_next_follow_the_chain(real_site):
    """Where the reader is, and the two steps out of a page.

    The register is the same entries on every page - every page of the index,
    in its order - so only the marker says where one stands; the `##` headings
    of the page one is on are the jump targets under it. Prev/next are the
    neighbours in the index's order, which is the `**Next:**` chain of the
    pages themselves.
    """
    order = site.page_order(_read("docs", "README.md"))
    with_headings = 0
    for i, name in enumerate(order):
        url = site.page_url(name)
        rel = "%s/index.html" % url
        html = real_site.read(rel)
        register = html[html.index('<aside class="register"'):html.index("</aside>")]
        # Every page of the index, in its order, on every page of the guide
        listed = re.findall(r'<a class="page-link" href="([^"]+)"', register)
        assert listed == ["../%s/" % site.page_url(other) for other in order], rel
        # Exactly one of them is marked as the one being read
        assert register.count('aria-current="page"') == 1, rel
        marked = re.search(r'href="([^"]+)" aria-current="page"', register)
        assert marked.group(1) == "../%s/" % url, rel
        assert register.count('class="page-entry is-current"') == 1, rel
        # ... and its own ## headings stand under it as jump targets. A page of
        # one section (docs/firewall.md is one) has none, and then there is
        # nothing to list - what may not happen is a target the page lacks or
        # one of its sections missing from the list.
        want = [hid for level, hid, _ in site.headings(html) if level == 2]
        heads = re.findall(r'<a class="head-link" href="#([^"]+)"', register)
        assert heads == want, rel
        with_headings += 1 if want else 0
        # Prev and next are the neighbours in the chain, which closes cyclically
        before, after = order[i - 1], order[(i + 1) % len(order)]
        assert '<a class="pager-prev" href="../%s/"' % site.page_url(before) in html, rel
        assert '<a class="pager-next" href="../%s/"' % site.page_url(after) in html, rel
        # The page's own **Next:** line says the same thing
        follows = re.search(r"^\*\*Next:\*\* \[[^\]]+\]\(([A-Za-z0-9_.-]+)\)",
                            _read("docs", name), re.M)
        if follows:
            assert follows.group(1) == after, name
    # A floor, because "the headings of the page stand under it" would hold
    # vacuously if the register suddenly listed none at all
    assert with_headings >= len(order) - 2, \
        "only %d of %d pages list their ## headings in the register" % (
            with_headings, len(order))


def test_the_guide_index_is_named_short_where_it_is_only_referred_to(real_site):
    """The index's own h1 is a title, not a list entry.

    "Transportable Detonation Chamber - Documentation" wraps to two lines in
    the register and reads oddly as "Previous: ...". The page keeps that h1,
    its <title> and its name in the search index; the register entry and the
    pager use the short name.
    """
    index_page = real_site.read("guide/index.html")
    full = site.TITLE + " \u2014 Documentation"
    short = site.SITE_SHORT_TITLES["README.md"]
    assert short and short != full
    # The page itself is unchanged: its h1, its title and its index entry
    assert ">%s</h1>" % site.esc(full) in index_page, "the index lost its own h1"
    assert "<title>%s</title>" % site.esc(full) in index_page
    data = json.loads(real_site.read(site.SITE_SEARCH))
    assert [p["title"] for p in data["pages"] if p["url"] == "guide"] == [full]
    # Where another page points at it, the short name stands
    for rel in real_site.pages():
        html = real_site.read(rel)
        if rel != "index.html":
            register = html[html.index('<aside class="register"'):html.index("</aside>")]
            entry = re.search(r'<a class="page-link" href="[^"]*guide/"[^>]*>'
                              r'([^<]+)</a>', register)
            assert entry, rel
            assert entry.group(1) == site.esc(short), "%s: %r" % (rel, entry.group(1))
        for found in re.finditer(r'<a class="pager-\w+" href="([^"]*)">'
                                 r'<span>[^<]*</span><b>([^<]+)</b></a>', html):
            if found.group(1).endswith("guide/"):
                assert found.group(2) == site.esc(short), "%s: %r" % (rel, found.group(2))
    # The two pages that point at it in the pager are its neighbours, so the
    # short name really is on the page and not only available
    neighbours = [rel for rel in real_site.pages()
                  if re.search(r'<b>%s</b>' % re.escape(site.esc(short)),
                               real_site.read(rel))]
    assert len(neighbours) == 2, neighbours


def test_the_footer_carries_date_and_commit_and_no_local_path(real_site, tmp_path):
    """The footer is what a reader quotes in an issue: when and from what.

    No local path and no machine name anywhere in the output - the build runs
    on a laptop and in the CI, and the result is published to the world.
    """
    built = _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"})
    html = built.read("setup/index.html")
    stamp = re.search(r'<time datetime="(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}Z">'
                      r'\1 \d{2}:\d{2} UTC</time>', html)
    assert stamp, "no build date in UTC"
    # UTC, not the clock of whoever built it (the suite runs under two zones)
    assert stamp.group(1) in (
        (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d"),
        datetime.datetime.utcnow().strftime("%Y-%m-%d"))
    commit = site.short_commit()
    if commit:
        assert "commit <code>%s</code>" % commit in html
    # The same page in the repository, from every page and from the front page
    assert site.REPO_BLOB + "docs/setup.md" in html
    assert site.REPO_BLOB + "README.md" in built.read("index.html")
    # An explicit date and commit render exactly as the footer promises
    page = {"name": "setup.md", "url": "setup", "title": "Setup", "html": "<h1>S</h1>",
            "headings": [(1, "setup", "Setup")], "prev": None, "next": None}
    alone = site.site_page(page, [page], datetime.datetime(2026, 11, 18, 7, 5, 9), "abc1234")
    assert '<time datetime="2026-11-18T07:05:09Z">2026-11-18 07:05 UTC</time>' in alone
    assert "commit <code>abc1234</code>" in alone
    # Mermaid is MIT and the site ships its code: the credit goes with it
    assert "Mermaid %s (MIT)" % site.MERMAID_VERSION in alone
    # Nothing in the real site names the machine that built it
    for rel in real_site.written:
        if not rel.endswith((".html", ".css", ".js", ".nojekyll")) or rel == site.SITE_WIKI:
            continue
        text = real_site.read(rel)
        # The guide itself writes about C:\Users\Public and about /home on the
        # host, which is its subject - so the shapes of a path are looked for
        # in what the generator writes, and the paths of this machine in
        # everything.
        chrome = _own_chrome(text) if rel.endswith(".html") else text
        for shape in ("/Users/", "/home/", "C:\\Users", "/private/var"):
            assert shape not in chrome, "%s names %s" % (rel, shape)
        for secret in (os.path.abspath(ROOT), real_site.dir, platform.node()):
            assert secret and secret not in text, "%s names %s" % (rel, secret)


def test_the_build_stops_before_it_writes_when_an_ingredient_is_missing(tmp_path):
    """Every gate runs before the first file, and says what to do.

    The folder is uploaded as it stands, so a build that cannot finish must not
    leave half of it behind - and a folder of an earlier build has to come out
    of a refused run exactly as it went in, because that is what is published
    until the next good build.
    """
    pages = {"setup.md": "# Setup\n\nText.\n"}
    good = _fixture_site(tmp_path, pages)
    before = _tree(good.dir)
    assert before, "the fixture wrote nothing"

    def refused(message_parts, these=pages, **broken):
        with pytest.raises(site.WikiError) as caught:
            _fixture_site(tmp_path, these, **broken)
        message = str(caught.value)
        for part in message_parts:
            assert part in message, "%r is not in %r" % (part, message)
        assert _tree(good.dir) == before, "a refused build changed the folder: %s" % message
        # ... and into a folder that is not there yet it writes nothing at all
        with pytest.raises(site.WikiError):
            _fixture_site(tmp_path, these, out="fresh", **broken)
        fresh = tmp_path / "fresh"
        assert not fresh.exists() or not list(fresh.iterdir())

    # The pinned Mermaid copy: a site whose diagrams are dead text is worse
    # than no site, and the checksum is the only thing that can tell
    refused(["Mermaid", site.MERMAID_SHA256, site.MERMAID_VERSION],
            mermaid="/* not the bundle this generator knows */")
    refused(["Mermaid", "missing"], mermaid=False)
    # A page the index links but docs/ does not have
    refused(["ghost.md", "does not exist"],
            these={"setup.md": "# Setup\n\nText.\n", "ghost.md": None})
    # The three the header and the footer promise on every page
    refused(["offline wiki", "make docs"], wiki=False)
    refused(["logo"], logo=False)
    refused(["README"], readme=False)
    # A picture is the gate of its own test, and it is the same shape
    refused(["static", "nope.png"],
            these={"setup.md": "# Setup\n\n![Gone](../static/nope.png)\n"})


def test_a_heading_cannot_take_an_id_the_page_shell_owns(tmp_path):
    """A docs heading never collides with the ids of the header and the shell.

    The shell writes id="content", "register", "search", "results",
    "search-count" and "search-hits" around the prose, and they come *first* in
    the document. A page with `## Content` or `## Search` would hand the
    heading the same id, and then the register's own `href="#search"` and every
    search hit for that section scroll to the search box instead of the
    section. The anchors of the prose are numbered against what the shell owns,
    not only against each other.
    """
    page = ("# Shell\n\n## Content\n\nAbout the content.\n\n"
            "## Search\n\nAbout the search.\n\n"
            "## Register\n\nAbout the register.\n\n"
            "## Results\n\nAbout the results.\n")
    built = _fixture_site(tmp_path, {"shell.md": page})
    html = built.read("shell/index.html")
    # Nothing on the page carries an id twice
    ids = re.findall(r'\sid="([^"]+)"', html)
    assert len(ids) == len(set(ids)), \
        "the page carries an id twice: %s" % sorted(
            i for i in ids if ids.count(i) > 1)
    # ... and no heading took one of the shell's
    taken = [hid for _, hid, _ in site.headings(html) if hid in site.SITE_SHELL_IDS]
    assert not taken, "a heading took the shell's id: %s" % taken
    # The register's jump targets are the headings, and they are the ones a
    # reader lands on: every one of them is the id of a heading, not of a box
    # of the shell
    register = html[html.index('<aside class="register"'):html.index("</aside>")]
    heads = re.findall(r'<a class="head-link" href="#([^"]+)"', register)
    assert heads == [hid for level, hid, _ in site.headings(html) if level == 2]
    for hid in heads:
        found = re.search(r'<h2 id="%s"' % re.escape(hid), html)
        assert found, "%s is not a heading of the page" % hid
    # And the shell still has its own, exactly once each
    for shell_id in site.SITE_SHELL_IDS:
        assert html.count(' id="%s"' % shell_id) == 1, shell_id


def test_the_build_refuses_a_page_the_index_forgot_and_a_link_to_nowhere(tmp_path):
    """Two gates the suite had and the build did not.

    tests.yml and pages.yml are separate workflows: a push to main publishes
    whatever `make site` writes, and the suite goes red *beside* it. So a page
    docs/ has and the index does not order - which would be dropped in silence
    - and a link to a folder that is no page of this site - which would be
    published dead - have to stop the build, not only the tests.
    """
    pages = {"setup.md": "# Setup\n\nText.\n", "logs.md": "# Logs\n\nText.\n"}
    good = _fixture_site(tmp_path, pages)
    before = _tree(good.dir)

    def refused(parts, these=pages, **broken):
        with pytest.raises(site.WikiError) as caught:
            _fixture_site(tmp_path, these, **broken)
        message = str(caught.value)
        for part in parts:
            assert part in message, "%r is not in %r" % (part, message)
        assert _tree(good.dir) == before, "a refused build changed the folder"
        return message

    # A page of docs/ that the index does not order has no address at all
    refused(["newthing.md", "docs/README.md"],
            unlisted={"newthing.md": "# New thing\n\nText.\n"})
    # ... and the message names both sides, so a maintainer can see which it is
    message = refused(["newthing.md"],
                      unlisted={"newthing.md": "# New thing\n\nText.\n"})
    assert "setup.md" not in message.split("newthing.md")[0] or "index" in message

    # A link to a page that is not being written is a 404 on the published site
    refused(["gone", "logs.md"],
            these={"setup.md": "# Setup\n\nText.\n",
                   "logs.md": "# Logs\n\nSee [the gone page](gone.md).\n"})
    # The same shape with an anchor on it
    refused(["gone"],
            these={"setup.md": "# Setup\n\nText.\n",
                   "logs.md": "# Logs\n\nSee [a section](gone.md#deep).\n"})
    # What may not be refused: the links the guide really writes - another
    # page, an anchor of this page, an anchor of another page, a picture, the
    # front page, a file of the repository and the web
    fine = {"setup.md": ("# Setup\n\n## Deep\n\nText.\n"),
            "logs.md": ("# Logs\n\nSee [Setup](setup.md), [its section]"
                        "(setup.md#deep), [here](#logs), [the index](README.md),"
                        " [the front page](../README.md), [a shot]"
                        "(../static/shot.png), [the Vagrantfile]"
                        "(../Vagrantfile.utm) and [the web](https://example.com).\n\n"
                        "![A shot](../static/shot.png)\n")}
    built = _fixture_site(tmp_path, fine)
    assert "logs/index.html" in built.written


def test_an_ordered_marker_that_is_not_one_does_not_cut_a_paragraph():
    """A wrapped sentence whose next line begins "3008) ..." stays a sentence.

    CommonMark: an ordered list may interrupt a paragraph only when it starts
    at 1. Without that rule the continuation line of a quote in docs/web-ui.md
    was read as a list marker, the paragraph was cut into three blocks and the
    token "3008)" vanished from the published page - in both outputs, because
    both use this parser.
    """
    wrapped = ("The tree holds three instances (PIDs 4052, 3964 and\n"
               "3008) with their switches, tags and endpoints; the map shows\n"
               "two arcs.\n")
    html = site.render_markdown(wrapped, {}, page="x.md")
    assert html.count("<p>") == 1, html
    assert "<ol" not in html and "<li>" not in html, html
    assert "3008)" in html, html
    # The same inside a blockquote, which is where the guide writes it
    quoted = site.render_markdown(
        "> " + wrapped.replace("\n", "\n> ").rstrip("> "), {}, page="x.md")
    assert quoted.count("<p>") == 1, quoted
    assert "3008)" in quoted and "<li>" not in quoted, quoted
    # A list that starts at 1 still interrupts a paragraph, as it always did
    interrupted = site.render_markdown("A sentence.\n1. one\n2. two\n", {}, page="x.md")
    assert "<ol" in interrupted and interrupted.count("<li>") == 2, interrupted
    # ... and a list that stands on its own keeps its own first number: the
    # rule is about interrupting, not about what a list may be numbered
    alone = site.render_markdown("Text.\n\n3. three\n4. four\n", {}, page="x.md")
    assert "<ol" in alone and alone.count("<li>") == 2, alone
    # A bullet interrupts a paragraph as before
    bullet = site.render_markdown("A sentence.\n- one\n- two\n", {}, page="x.md")
    assert "<ul" in bullet and bullet.count("<li>") == 2, bullet
    # And the page the finding came from carries the whole sentence
    page = _read("docs", "web-ui.md")
    assert "3008) with their ALLOW switches" in page, "the markdown moved"
    rendered = site.render_markdown(page, {}, page="web-ui.md",
                                    links=site.site_link_target, scoped=False,
                                    net_note=False)
    assert "3008) with their ALLOW switches" in rendered.replace("\n", " "), \
        "the published paragraph still loses its token"


def test_no_page_of_the_site_says_it_needs_a_network(real_site):
    """The website is read over the network; the note belongs to the wiki.

    Every link into the repository carries "(needs network access, which the VM
    does not have)" in the offline wiki, which is read on a machine that has
    none. On the site that sentence is wrong, and net_note=False is one keyword
    argument away from being lost: flipping it changed no test before this one.
    """
    for rel in real_site.pages():
        html = real_site.read(rel)
        assert 'class="net-note"' not in html, rel
        assert site.NETWORK_NOTE not in html, rel
    # The wiki, built from the same parser, does carry it: the note was not
    # deleted, it is left off here
    page = site.render_markdown("See the [Vagrantfile](../Vagrantfile.utm).\n",
                                {}, page="setup.md")
    assert site.NETWORK_NOTE in page


def test_a_second_build_leaves_nothing_of_the_first_behind(tmp_path):
    """A renamed page would otherwise keep its old folder.

    The folder is uploaded as it stands, so a page nobody links any more would
    still be published - the guide as it was some commits ago, with no way for
    a reader to tell. The build sweeps what it wrote itself and nothing else:
    it keeps the list, and a file somebody else put there is not on it.
    """
    built = _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n",
                                     "gone.md": "# Gone\n\nAn address of this build.\n"},
                          images=("shot.png", "extra.png"))
    assert site.SITE_MANIFEST in built.written, "the build keeps no list of what it wrote"
    assert "gone/index.html" in built.written
    assert "assets/img/extra.png" in built.written
    # Two files somebody else put into the folder: they are on no list of ours
    kept = os.path.join(built.dir, "CNAME")
    with open(kept, "w") as fh:
        fh.write("docs.example.test\n")
    mine = os.path.join(built.dir, "mine")
    os.mkdir(mine)
    with open(os.path.join(mine, "notes.txt"), "w") as fh:
        fh.write("not the build's\n")
    # A commit that drops a page and a picture
    os.remove(str(tmp_path / "docs" / "gone.md"))
    os.remove(str(tmp_path / "static" / "extra.png"))
    again = _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"}, images=("shot.png",))
    assert "gone/index.html" not in again.written
    assert not os.path.exists(os.path.join(built.dir, "gone")), \
        "a page of an earlier build is still published"
    assert not os.path.exists(os.path.join(built.dir, "assets", "img", "extra.png"))
    assert os.path.isfile(os.path.join(built.dir, "setup", "index.html"))
    assert os.path.isfile(os.path.join(built.dir, "assets", "img", "shot.png"))
    assert os.path.isfile(kept), "the build deleted a file it never wrote"
    assert os.path.isfile(os.path.join(mine, "notes.txt"))
    # ... and a third build does not get to them either
    _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"}, images=("shot.png",))
    assert os.path.isfile(kept) and os.path.isfile(os.path.join(mine, "notes.txt"))


def test_a_manifest_cannot_reach_outside_the_build_folder(tmp_path):
    """The list is a file in the folder, so it is an input, not a fact.

    Whoever can write one line into it would otherwise have the build delete
    any path the builder can reach - in the CI too: the sweep joined every
    entry to the folder, which for an absolute entry is that absolute path,
    and the folder climb that follows walked out of the build folder with it.
    A list that names anything but a file inside the folder is not a list of
    ours, and the folder is refused as any folder we cannot account for.
    """
    pages = {"setup.md": "# Setup\n\nText.\n"}
    outside = tmp_path / "outside"
    outside.mkdir()

    def plant():
        """The builder's own files, beside the build folder."""
        (outside / "victim.txt").write_text("a file of the builder\n", encoding="utf-8")
        deep = outside / "keepme" / "a" / "b"
        os.makedirs(str(deep), exist_ok=True)
        (deep / "file.txt").write_text("deep\n", encoding="utf-8")
        return _tree(str(outside))

    hostile = [
        str(outside / "victim.txt"),          # an absolute path
        "../outside/victim.txt",              # one step out
        "../outside/keepme/a/b/file.txt",     # and the folders above it
        "assets/../../outside/victim.txt",    # a step out in the middle
        "C:\\Windows\\System32\\drivers\\etc\\hosts",  # a drive letter
        "\\\\server\\share\\file.txt",        # a share
        "..",                                 # the folder above
        ".",                                  # the folder itself
    ]
    for line in hostile:
        built = _fixture_site(tmp_path, pages)
        before = plant()
        with open(os.path.join(built.dir, site.SITE_MANIFEST), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        with pytest.raises(site.WikiError) as caught:
            _fixture_site(tmp_path, pages)
        assert "no build of this site wrote" in str(caught.value), line
        assert _tree(str(outside)) == before, "%r reached out of the folder" % line
        # The folder itself is left as it was, too: it is not ours to sweep
        assert os.path.isfile(os.path.join(built.dir, "setup", "index.html"))
        os.remove(os.path.join(built.dir, site.SITE_MANIFEST))
        for name in os.listdir(built.dir):
            path = os.path.join(built.dir, name)
            if os.path.isfile(path):
                os.remove(path)
            else:
                for folder, _, names in os.walk(path, topdown=False):
                    for leaf in names:
                        os.remove(os.path.join(folder, leaf))
                    os.rmdir(folder)

    # A list that is not a file at all, and one that was cut off mid-write
    built = _fixture_site(tmp_path, pages)
    before = plant()
    manifest = os.path.join(built.dir, site.SITE_MANIFEST)
    os.remove(manifest)
    os.mkdir(manifest)
    with pytest.raises(site.WikiError) as caught:
        _fixture_site(tmp_path, pages)
    assert "no build of this site wrote" in str(caught.value)
    assert _tree(str(outside)) == before
    os.rmdir(manifest)

    # A truncated list names fewer files than are there, which costs a sweep,
    # never a wrong delete: every line of it is still a file of the folder
    with open(manifest, "w", encoding="utf-8") as fh:
        fh.write("setup/index.html\nassets/sty")
    again = _fixture_site(tmp_path, pages)
    assert os.path.isfile(os.path.join(again.dir, "setup", "index.html"))
    assert _tree(str(outside)) == before

    # A path the list names that is a directory now: this build writes files,
    # so a directory in their place is somebody else's and stays
    stood = os.path.join(again.dir, "assets", "img", "shot.png")
    os.remove(stood)
    os.mkdir(stood)
    with open(os.path.join(stood, "theirs.txt"), "w") as fh:
        fh.write("not the build's\n")
    os.remove(str(tmp_path / "static" / "shot.png"))
    third = _fixture_site(tmp_path, pages, images=())
    assert "assets/img/shot.png" not in third.written
    assert os.path.isfile(os.path.join(stood, "theirs.txt")), \
        "the sweep took a directory and what was in it"


def test_the_sweep_and_its_fence_hold_on_their_own(tmp_path):
    """The second layer, tested where it can be reached.

    A hostile line never gets as far as the sweep today, because the list is
    refused before that - so the fence inside the sweep is tested here
    directly, where a later caller that hands a list over unchecked would land.
    """
    out = tmp_path / "site"
    (out / "a" / "b").mkdir(parents=True)
    (out / "a" / "b" / "page.html").write_text("ours", encoding="utf-8")
    # A sibling whose name begins with the build folder's own name: a fence
    # built on "starts with" would let this through
    neighbour = tmp_path / "site-notes"
    neighbour.mkdir()
    (neighbour / "file.txt").write_text("the builder's notes", encoding="utf-8")
    assert site._inside(str(out), str(out / "a" / "b" / "page.html")) is True
    assert site._inside(str(out), str(out)) is False
    assert site._inside(str(out), str(neighbour / "file.txt")) is False
    assert site._inside(str(out), str(tmp_path / "outside.txt")) is False

    victim = tmp_path / "victim.txt"
    victim.write_text("a file of the builder", encoding="utf-8")
    hostile = [str(victim), "../victim.txt", "../site-notes/file.txt",
               "a/../../victim.txt", "C:\\Windows\\x", "..", "."]
    site._drop_stale(str(out), hostile, [])
    assert victim.is_file(), "the sweep reached outside the folder it owns"
    assert (neighbour / "file.txt").is_file()
    assert neighbour.is_dir() and tmp_path.is_dir()
    # What it does sweep: a path of its own that this build no longer writes,
    # and the folders that held it, up to the build folder and no further
    site._drop_stale(str(out), ["a/b/page.html"], [])
    assert not (out / "a").exists()
    assert out.is_dir(), "the sweep took the build folder itself"


def test_an_interrupted_build_can_be_built_again(tmp_path, monkeypatch):
    """A Ctrl-C in the middle may not leave a folder nobody can build into.

    The list is written before the first file, so a folder that was half
    written is still a folder the next build can account for - otherwise the
    only way out is deleting it by hand, and in the CI there is nobody to do
    that.
    """
    pages = {"setup.md": "# Setup\n\nText.\n",
             "gone.md": "# Gone\n\nAn address of this build.\n"}
    real = site._write_copy
    copied = []

    def interrupted(out_dir, rel, source):
        copied.append(rel)
        if len(copied) == 2:
            raise KeyboardInterrupt("Ctrl-C in the middle of the copies")
        return real(out_dir, rel, source)

    monkeypatch.setattr(site, "_write_copy", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _fixture_site(tmp_path, pages)
    out = tmp_path / "site"
    assert (out / site.SITE_MANIFEST).is_file(), "the half-written folder has no list"
    assert (out / "gone" / "index.html").is_file(), "the pages are written before the copies"
    monkeypatch.undo()
    # The next build takes the folder over - and still sweeps the page that
    # the interrupted build wrote and this one does not
    os.remove(str(tmp_path / "docs" / "gone.md"))
    built = _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"})
    assert os.path.isfile(os.path.join(built.dir, "setup", "index.html"))
    assert not os.path.exists(os.path.join(built.dir, "gone"))
    assert os.path.isfile(os.path.join(built.dir, "assets", "mermaid.min.js"))


def test_a_folder_the_build_does_not_know_is_refused(tmp_path):
    """Fifty-three files into somebody's folder is not a build, it is a mess.

    A folder with things in it and no list of ours is not a site this build
    made: it is refused, with nothing written, rather than mixed into.
    """
    _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"})  # the ingredients
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "important.txt").write_text("not the build's", encoding="utf-8")
    (other / "mine").mkdir()
    (other / "mine" / "notes.txt").write_text("nor this", encoding="utf-8")
    before = _tree(str(other))
    for _ in range(2):
        with pytest.raises(site.WikiError) as caught:
            _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"}, out="elsewhere")
        assert "elsewhere" in str(caught.value)
        assert _tree(str(other)) == before, "the build wrote into a foreign folder"
    # An empty folder is fine, and the second build into it is ours
    empty = tmp_path / "empty"
    empty.mkdir()
    built = _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"}, out="empty")
    assert os.path.isfile(os.path.join(built.dir, "setup", "index.html"))
    _fixture_site(tmp_path, {"setup.md": "# Setup\n\nText.\n"}, out="empty")


def test_the_command_line_builds_a_site_from_its_own_arguments(tmp_path, capsys):
    """Every ingredient is an argument, so a site can be built from a fixture.

    Without that, --site could only ever build this repository's own README and
    logo, and a hostile fixture site (Task 6) could not be built at all.
    """
    pages = {"setup.md": "# Setup\n\nText.\n"}
    _fixture_site(tmp_path, pages, out="first")  # writes the ingredients
    out = tmp_path / "cli"
    code = site.main(["--site", str(out),
                      "--docs", str(tmp_path / "docs"),
                      "--static", str(tmp_path / "static"),
                      "--mermaid", MERMAID,
                      "--readme", str(tmp_path / "README.md"),
                      "--logo", str(tmp_path / "tdc-logo.png"),
                      "-o", str(tmp_path / "wiki.html")])
    assert code == 0
    said = capsys.readouterr()
    # the front page, the fixture's own index and the one page
    assert "[site]" in said.out and "3 pages" in said.out, said.out
    assert os.path.isfile(str(out / "index.html"))
    assert os.path.isfile(str(out / "setup" / "index.html"))
    assert os.path.isfile(str(out / "assets" / "style.css"))
    # A refused build is reported, not raised, and sets the exit code
    code = site.main(["--site", str(tmp_path / "broken"),
                      "--docs", str(tmp_path / "docs"),
                      "--static", str(tmp_path / "static"),
                      "--mermaid", MERMAID,
                      "--readme", str(tmp_path / "nothere.md"),
                      "--logo", str(tmp_path / "tdc-logo.png"),
                      "-o", str(tmp_path / "wiki.html")])
    assert code == 1
    assert "[site]" in capsys.readouterr().err
    assert not (tmp_path / "broken").exists()


def _ps_arm(source, name):
    """The body of one `'name' { ... }` arm of make.ps1's switch.

    Found by the arm that follows it at the same indentation, not by the name
    of a particular one: the arms may be reordered without this going blind.
    """
    start = source.index("    '%s' {" % name)
    rest = source[start + 1:]
    following = re.search(r"\n    '[a-z0-9-]+' \{", rest)
    return rest[:following.start()] if following else rest


def test_the_make_targets_build_and_serve_the_site():
    """`make site` must build the wiki first: the download the header promises
    is git-ignored and is not there in a fresh clone, and a preview that lacks
    it is not what gets published."""
    makefile = _read("Makefile")
    assert re.search(r"^\.PHONY: site$", makefile, re.M)
    assert re.search(r"^site: docs$", makefile, re.M), "make site does not build the wiki"
    assert re.search(r"^\.PHONY: site-serve$", makefile, re.M)
    assert re.search(r"^site-serve:", makefile, re.M)
    assert "--site" in makefile
    assert "http.server" in makefile, "nothing serves the build folder"
    assert "make site" in makefile and "make site-serve" in makefile, \
        "the two targets are not in `make help`"
    ps = _read("make.ps1")
    allowed = ps[ps.index("ValidateSet("):ps.index(")]", ps.index("ValidateSet("))]
    assert "'site'" in allowed and "'site-serve'" in allowed, \
        "the targets are not in make.ps1's ValidateSet"
    assert re.search(r"'site'\s*\{", ps) and re.search(r"'site-serve'\s*\{", ps)
    assert "--site" in ps and "http.server" in ps
    assert ".\\make.ps1 site" in ps and ".\\make.ps1 site-serve" in ps
    # The same two knobs as the Makefile, so the front ends cannot drift
    assert "$SiteDir" in ps and "$SitePort" in ps
    assert re.search(r"\[string\]\$SiteDir\s*=\s*'site'", ps)
    assert re.search(r"\[int\]\$SitePort\s*=\s*8099", ps)
    # The preview changes directory, so its interpreter has to be resolved
    # before that: a relative path is looked for inside the folder being
    # served, where there is no venv, and the fallback to a bare "python" only
    # happens when the venv is absent - so it fails in the normal case.
    serve = _ps_arm(ps, "site-serve")
    assign = re.search(r"\$SitePy\s*=\s*Join-Path\s+\$PSScriptRoot", serve)
    push = re.search(r"^\s*Push-Location\b", serve, re.M)
    assert assign, "site-serve does not resolve its Python from the script's own folder"
    assert push, "site-serve does not change into the folder it serves"
    assert assign.start() < push.start(), \
        "site-serve resolves its Python after Push-Location, so it is looked for " \
        "inside the folder being served"
    assert re.search(r"&\s*\$SitePy\s+-m\s+http\.server", serve), \
        "site-serve does not run the resolved interpreter"
    # And `site` builds the wiki by calling the `docs` arm, not by repeating
    # its body: two copies of the same three lines drift apart, and the
    # Makefile says `site: docs` for the same reason
    arm = _ps_arm(ps, "site")
    assert re.search(r"&\s*\$PSCommandPath\s+docs\b", arm), \
        "the site arm does not call the docs arm: %r" % arm[:300]
    assert "build-wiki.py -o" not in arm.replace("\\", "/"), \
        "the site arm still builds the wiki itself"
    assert arm.count("build-wiki.py") == 1, arm
    # The build folder is generated, like the wiki: it is never committed
    assert re.search(r"^/site/$", _read(".gitignore"), re.M)


# --- Every address against its markdown, word for word ----------------------
#
# The test below is the one that would have caught the paragraph docs/web-ui.md
# lost to the ordered-list rule: a crude token comparison found it, and nothing
# in the suite did. It holds every address against the markdown it is made of -
# not the shape of the page, the words on it, in their order.
#
# What the page does *not* show, and the tokeniser therefore drops from the
# markdown:
#
#  * the info string of a fence (```bash): it names the language, the page
#    carries it as a class. The body of the fence is kept, mermaid included,
#    because the page carries that as text.
#  * the target of a link and of a picture: ](../rizin/) is an address, not a
#    word. The label of a link is kept; the alternative text of a picture is
#    held separately, as an attribute.
#  * a markdown marker: #, *, _, `, >, the - or 1. of a list item, the | and
#    the --- of a table. They are punctuation of the source, not of the page.
#  * an entity name: &mdash; in the source is a dash on the page, so the source
#    is unescaped before it is compared.
#  * the raw HTML the README writes for its hero, its badges and its feature
#    pictures. Those blocks are the front page's own two forms, and what of
#    them the page shows is its own rule: a badge's alt is a chip and is
#    visible, a screenshot's alt is a picture's attribute and is not.

_MD_FENCE = re.compile(r"^(\s{0,3})(`{3,}|~{3,})\s*([\w+.-]*)\s*$")
_MD_DELIM = re.compile(r"^\s*\|?(?:\s*:?-+:?\s*\|)+\s*:?-*:?\s*\|?\s*$")
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
_HTML_TAG = re.compile(r"<[^>]+>")
_SHIELD = re.compile(r'<img\s[^>]*src="https://img\.shields\.io[^"]*"'
                     r'[^>]*alt="([^"]*)"[^>]*>')
# A word is a run of letters and digits; punctuation and markers are
# separators on both sides. A tag of the page becomes a space, so `vagrant`/`vagrant`
# is "vagrant / vagrant" there and "vagrant/vagrant" in the source - the same two
# words either way, which is what is compared. A word that is dropped is gone from
# the stream whatever hangs off it, and two words run together without a space are
# one word and are caught.
_WORD = re.compile(r"[^\W_]+", re.UNICODE)


def _words(text):
    return _WORD.findall(text)


def _markdown_words(text, front=False):
    """The words a page made of this markdown shows, in order.

    `front` is the README: its raw HTML blocks are the front page's hero, its
    badge chips and its feature pictures, so a badge's alternative text is a
    word on the page and a screenshot's is not.
    """
    out = []
    fence = None
    in_list = False
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            in_list = False
        found = _MD_FENCE.match(line)
        if fence is None and found:
            fence = found.group(2)[:3]
            continue                     # the info string is a class, not a word
        if fence is not None:
            if re.match(r"^\s{0,3}(%s)+\s*$" % re.escape(fence), line):
                fence = None
                continue
            out.append(html_module.unescape(line))
            continue
        if _MD_DELIM.match(line) and "|" in line:
            continue                     # the ---|--- of a table head
        if re.match(r"^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$", line):
            continue                     # a horizontal rule
        body = line
        if front:
            # A badge is a chip: its label is on the page. Every other raw tag
            # is markup of the hero or of a picture.
            body = _SHIELD.sub(lambda m: " %s " % m.group(1), body)
        # An inline code span is held back first: it is text on the page, and
        # the guide writes `--vm-ip <vm-ip>` in one, where the angle brackets
        # are a placeholder a reader types over and not a tag to strip.
        spans = []

        def hold(found):
            spans.append(found.group(1))
            return "\0%d\0" % (len(spans) - 1)

        body = re.sub(r"`([^`]*)`", hold, body)
        body = _MD_IMAGE.sub(" ", body)                      # alt held separately
        body = _MD_LINK.sub(lambda m: " %s " % m.group(1), body)
        if front:
            # Only the README's raw HTML is markup; on a page of the guide the
            # parser escapes every angle bracket, so "Restarted: <names>." is
            # four words there and not a tag.
            body = _HTML_TAG.sub(" ", body)
        body = re.sub(r"\0(\d+)\0", lambda m: " %s " % spans[int(m.group(1))], body)
        body = re.sub(r"^\s{0,3}>\s?", " ", body)            # a quote marker
        # The number of a list item would be a word, and the page draws it from
        # the list instead, so the marker goes - but only where it is one. An
        # ordered marker interrupts a paragraph only when it starts at 1
        # (CommonMark), which is why "3008) with their ALLOW switches" is four
        # words of a sentence and not an item of a list. `#`, `|`, `*` and a
        # backtick are no word characters and fall out by themselves.
        marker = re.match(r"^(\s*)([-*+]|\d{1,9}[.)])\s+", body)
        if marker and (not marker.group(2)[0].isdigit()
                       or marker.group(2)[:-1] == "1" or in_list):
            body = body[:marker.end(1)] + body[marker.end():]
            in_list = True
        elif body.startswith("  ") and body.strip():
            pass                         # a wrapped line of the item above
        else:
            in_list = False
        out.append(html_module.unescape(body))
    return _words(" ".join(out))


def _page_words(html):
    """The words the written page shows, in order: its prose and nothing else.

    The register, the pager and the footer are the generator's own chrome and
    are held by their own tests; what is compared here is the article the
    markdown became.
    """
    start = html.index('<article class="prose">') + len('<article class="prose">')
    # ... to the *last* close: the front page's feature cards are articles of
    # their own inside it, so the first one would cut the page off at the
    # first card.
    prose = html[start:html.rindex("</article>")]
    prose = re.sub(r"<br\s*/?>", " ", prose)
    return _words(html_module.unescape(_HTML_TAG.sub(" ", prose)))


def _page_alts(html):
    """The alternative text of every picture of the prose, in order."""
    start = html.index('<article class="prose">')
    prose = html[start:html.rindex("</article>")]
    return [html_module.unescape(m.group(1)) for m in
            re.finditer(r'<img\b[^>]*\balt="([^"]*)"', prose)]


def test_every_address_carries_every_word_of_its_markdown(real_site):
    """Nothing of a page is dropped, swallowed or re-ordered on the way out.

    One source, said the spec: the website is the same sentences as docs/ and
    the README. The tests around this one hold the *shape* of a page - its
    headings, its links, its pictures, its tables - and a paragraph can be cut
    in three, or a token eaten by a marker that was mistaken for a list, with
    every one of them green. That is what happened to docs/web-ui.md.
    """
    order = site.page_order(_read("docs", "README.md"))
    checked = 0
    for name in order:
        rel = "%s/index.html" % site.page_url(name)
        html = real_site.read(rel)
        want = _markdown_words(_read("docs", name))
        got = _page_words(html)
        assert want, name
        if want != got:
            # Say where, not only that: the first token that differs and its
            # neighbours is what a maintainer needs
            for at, (a, b) in enumerate(zip(want, got)):
                if a != b:
                    raise AssertionError(
                        "%s differs from docs/%s at word %d:\n"
                        "  markdown: %s\n  page:     %s"
                        % (rel, name, at, " ".join(want[max(0, at - 8):at + 8]),
                           " ".join(got[max(0, at - 8):at + 8])))
            raise AssertionError(
                "%s has %d words, docs/%s has %d; the %s ends with: %s"
                % (rel, len(got), name, len(want),
                   "page" if len(got) < len(want) else "markdown",
                   " ".join((want if len(want) > len(got) else got)[len(got) - 8:])))
        # ... and every picture keeps the words that stand in for it
        assert _page_alts(html) == [alt for alt, _ in
                                    _MD_IMAGE.findall(_read("docs", name))], name
        checked += 1
    # The front page is the README, with its own two raw forms
    front = _page_words(real_site.read("index.html"))
    for word in _markdown_words(README, front=True):
        assert word in front, "the front page lost %r" % word
    # ... and in order: the first of every ten, so a reordered section shows
    wanted = _markdown_words(README, front=True)
    at = 0
    for word in wanted[::10]:
        at = front.index(word, at)
    assert checked == len(order), checked

#
# The index is a file of the site, fetched when the reader first types. The
# wiki carries its index inside the document because it is read from file://
# with no server behind it; the website is served, so the index is a file -
# every page would otherwise carry the same 200 KB of JSON.
#
# Two things are easy to get wrong and silent when they are: the anchors (the
# wiki's `search_records` emits its own scoped ones, `rizin--limits`, which no
# page of the site carries), and the hits (a line of a docs page is text, and
# a page that builds it as markup runs the guide's `<script>` examples under
# the repository's own origin).

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")

# The code goes to node on stdin: Linux takes no argument over 128 KiB and the
# real index is 200 KB (the pattern of tests/test_frontend.py).
_NODE_STDIN = ("require('vm').runInThisContext(require('fs').readFileSync(0, 'utf8'), "
               "{ filename: '[eval]' });")

# Enough of a browser for assets/site.js: the header's search box with its
# field and its empty result list, a document that answers the selectors the
# script asks for, and a fetch that hands out the index under test. Nothing
# here parses markup - innerHTML does not exist in this stub, so a hit that
# was built as markup would arrive as the text it is and the test would see
# the tags in it.
SITE_DOM = r"""
var fetched = [], focused = [], went = [], prevented = [], scrolled = [], pending = [];
var docListeners = {};

function classes() {
  var set = {};
  return {
    add: function (c) { set[c] = true; },
    remove: function (c) { delete set[c]; },
    contains: function (c) { return !!set[c]; },
    toggle: function (c, on) {
      if (on === undefined) { on = !set[c]; }
      if (on) { set[c] = true; } else { delete set[c]; }
      return on;
    }
  };
}

function element(tag) {
  var el = {
    tagName: tag.toUpperCase(), children: [], attrs: {}, own: '', className: '',
    classList: classes(), hidden: false, value: '', id: '', parent: null, listeners: {},
    appendChild: function (child) { child.parent = this; this.children.push(child); return child; },
    setAttribute: function (k, v) { this.attrs[k] = String(v); },
    getAttribute: function (k) { return k in this.attrs ? this.attrs[k] : null; },
    removeAttribute: function (k) { delete this.attrs[k]; },
    addEventListener: function (t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); },
    focus: function () { focused.push(this.id || this.tagName); },
    blur: function () {},
    scrollIntoView: function () { scrolled.push(this.textContent.slice(0, 20)); },
    contains: function (other) {
      for (var at = other; at; at = at.parent) { if (at === this) { return true; } }
      return false;
    },
    querySelector: function () { return null; },
    querySelectorAll: function () { return []; }
  };
  Object.defineProperty(el, 'textContent', {
    get: function () {
      return this.own + this.children.map(function (c) { return c.textContent; }).join('');
    },
    set: function (value) { this.children = []; this.own = String(value); }
  });
  return el;
}

var field = element('input');
field.id = 'search';
var hits = element('div');
hits.id = 'search-hits';
var count = element('p');
count.id = 'search-count';
var results = element('div');
results.id = 'results';
results.hidden = true;
results.appendChild(count);
results.appendChild(hits);
var box = element('div');
box.className = 'site-search';
box.setAttribute('data-root', ROOT);
box.appendChild(field);
box.appendChild(results);
var body = element('body');
var els = { search: field, results: results, 'search-hits': hits,
            'search-count': count, register: null };
var selectors = { '.site-search': box, '.register-toggle': null, '.top': null };

globalThis.document = {
  body: body,
  getElementById: function (id) { return id in els ? els[id] : null; },
  querySelector: function (sel) { return sel in selectors ? selectors[sel] : null; },
  querySelectorAll: function () { return []; },
  addEventListener: function (t, fn) { (docListeners[t] = docListeners[t] || []).push(fn); },
  createElement: function (tag) { return element(tag); },
  createTextNode: function (text) {
    return { tagName: '#text', className: '', children: [], textContent: String(text), parent: null };
  }
};
globalThis.location = {
  hash: '', href: '/rizin/',
  assign: function (url) { went.push(url); }
};
globalThis.history = { replaceState: function () {} };
globalThis.window = {
  location: globalThis.location,
  addEventListener: function () {},
  requestAnimationFrame: function (fn) { fn(); }
};
globalThis.fetch = function (url) {
  fetched.push(url);
  var answer = ANSWER.ok
    ? { ok: true, status: 200, json: function () { return Promise.resolve(INDEX); } }
    : { ok: false, status: ANSWER.status,
        json: function () { return Promise.reject(new Error('no body')); } };
  if (ANSWER.hold) {
    // The file is on its way and has not arrived: what a reader who keeps
    // typing sees, and the only state in which fetching twice can happen.
    return new Promise(function (resolve) { pending.push(function () { resolve(answer); }); });
  }
  return Promise.resolve(answer);
};

function release() {
  pending.splice(0).forEach(function (answer) { answer(); });
}

function fire(target, type, extra) {
  var event = { type: type, target: target, preventDefault: function () { prevented.push(type); },
                stopPropagation: function () {} };
  for (var key in (extra || {})) { event[key] = extra[key]; }
  (target.listeners[type] || []).slice().forEach(function (fn) { fn(event); });
}

function fireDoc(type, extra) {
  var event = { type: type, target: body, preventDefault: function () { prevented.push(type); },
                stopPropagation: function () {} };
  for (var key in (extra || {})) { event[key] = extra[key]; }
  (docListeners[type] || []).slice().forEach(function (fn) { fn(event); });
}

function flush() { return new Promise(function (done) { setTimeout(done, 0); }); }

async function typed(value) {
  field.value = value;
  fire(field, 'input');
  await flush();
  await flush();
}

function parts(node) {
  return node.children.map(function (span) {
    return {
      cls: span.className, text: span.textContent,
      tags: span.children.map(function (child) { return child.tagName; }),
      texts: span.children.map(function (child) { return child.textContent; }),
      marks: span.children.filter(function (child) { return child.tagName === 'MARK'; })
                          .map(function (child) { return child.textContent; })
    };
  });
}

function shown() {
  var out = { hidden: !!results.hidden, note: count.textContent, hits: [],
              expanded: field.getAttribute('aria-expanded'),
              current: field.getAttribute('aria-activedescendant') };
  hits.children.forEach(function (child) {
    out.hits.push({ tag: child.tagName, href: child.getAttribute('href'),
                    id: child.id, role: child.getAttribute('role'),
                    selected: child.getAttribute('aria-selected'),
                    active: child.classList.contains('is-active'),
                    text: child.textContent, parts: parts(child) });
  });
  return out;
}
"""

# A page whose every line is an attack on a search that builds its hits as
# markup, in the shape the index has.
HOSTILE_INDEX = {
    "pages": [{"url": "evil", "title": "<img src=x onerror=alert(1)>"}],
    "records": [[0, "shell", "A <script>alert(2)</script> heading",
                 "</a><script>alert(3)</script><img src=x onerror=alert(4)> onerror lives here"]],
}


def _shipped(real_site):
    """`assets/site.js` as it is published - what a behaviour test has to run."""
    return real_site.read(site.SITE_SCRIPT)


def _run_site_js(script, index, js, root="../", ok=True, status=200, hold=False):
    """Run the shipped assets/site.js in node against the stub above.

    `index` is what the stubbed fetch answers with (the real search.json as a
    string, or a dict), `js` the script under test (the written file, so the
    tests exercise what readers get), `script` the test's own code, which
    prints one JSON object. With `hold` the answer waits for the script's own
    `release()` - the reader who keeps typing while the file is on its way.
    """
    raw = index if isinstance(index, str) else json.dumps(index, ensure_ascii=False)
    code = "\n".join([
        "var INDEX = %s;" % raw,
        "var ROOT = %s;" % json.dumps(root),
        "var ANSWER = {ok: %s, status: %d, hold: %s};"
        % ("true" if ok else "false", status, "true" if hold else "false"),
        SITE_DOM, js, script])
    out = subprocess.run([NODE, "-e", _NODE_STDIN], input=code,
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_index_covers_every_page_and_its_shape_is_json(real_site, tmp_path):
    """One file, one entry per page of the guide, and every page has lines in it.

    A page missing from the index is a page the search cannot find, which is
    the one failure of a search nobody notices: the reader types a word that
    is in the guide and gets nothing.
    """
    raw = real_site.read(site.SITE_SEARCH)
    data = json.loads(raw)
    assert site.SITE_SEARCH in real_site.written
    assert sorted(data) == ["pages", "records"], sorted(data)
    order = site.page_order(_read("docs", "README.md"))
    assert [page["url"] for page in data["pages"]] == [site.page_url(n) for n in order]
    # The line above is the whole claim: every page of the index, in its order.
    # The floor only says that the index was read at all.
    assert len(data["pages"]) >= 12, \
        "the index covers %d pages: %s" % (len(data["pages"]),
                                           [p["url"] for p in data["pages"]])
    for page in data["pages"]:
        assert sorted(page) == ["title", "url"], page
        assert page["title"] and not page["title"].startswith("<"), page
        assert "%s/index.html" % page["url"] in real_site.written, page
    # The records: page, jump target, heading, line - and nothing else
    lines = {}
    for record in data["records"]:
        assert len(record) == 4, record
        at, anchor, heading, line = record
        assert isinstance(at, int) and 0 <= at < len(data["pages"]), record
        for part in (anchor, heading, line):
            assert isinstance(part, str), record
        assert line.strip(), record
        lines[at] = lines.get(at, 0) + 1
    for i, page in enumerate(data["pages"]):
        assert lines.get(i, 0) > 10, "%s has %d lines in the index" % (page["url"], lines.get(i, 0))
    assert len(data["records"]) > 1000, \
        "the index holds %d lines for a guide of %d pages; a guide this size " \
        "has thousands, so the sectioning probably dropped them" % (
            len(data["records"]), len(data["pages"]))
    # A site of three pages has the same shape, so the index is not a property
    # of this repository's guide
    built = _fixture_site(tmp_path, {"one.md": "# One\n\nA line about one.\n",
                                     "two.md": "# Two\n\n## Deep\n\nA line about two.\n"})
    small = json.loads(built.read(site.SITE_SEARCH))
    assert [p["url"] for p in small["pages"]] == ["guide", "one", "two"]
    assert all(len(r) == 4 for r in small["records"])
    assert [r for r in small["records"] if r[3] == "A line about two."] == \
        [[2, "deep", "Deep", "A line about two."]]


def test_a_word_from_a_deep_page_is_found_with_page_and_heading(real_site):
    """A word that stands on one page only names that page and its heading.

    Spec section 5's own wording. "hexdump" is in docs/rizin.md and in no
    other page of the guide; the test reads that rather than trusting it, so a
    docs change says so instead of passing on a word that moved.
    """
    term = "hexdump"
    where = sorted(name for name in os.listdir(DOCS)
                   if name.lower().endswith(".md") and term in _read("docs", name).lower())
    assert where == ["rizin.md"], \
        "%r is no longer a word of docs/rizin.md alone: %s" % (term, where)
    data = json.loads(real_site.read(site.SITE_SEARCH))
    hits = [r for r in data["records"] if term in r[3].lower()]
    assert hits, "the index has no line with %r in it" % term
    assert set(data["pages"][r[0]]["url"] for r in hits) == {"rizin"}
    assert set(data["pages"][r[0]]["title"] for r in hits) == {"Rizin"}
    # The heading it stands under, and the anchor of that heading on the page
    assert set(r[2] for r in hits) == {"Console without a shell"}, set(r[2] for r in hits)
    assert set(r[1] for r in hits) == {"console-without-a-shell"}
    assert 'id="console-without-a-shell"' in real_site.read("rizin/index.html")


def test_every_jump_target_of_the_index_exists_on_its_page(real_site):
    """Every anchor of the index is an id of the page the record names.

    `search_records` emits the wiki's scoped anchors ("rizin--limits"), which
    no page of the site carries: a record handed on unconverted sends the
    reader to the top of the page instead of to the line he searched for, and
    nothing in the browser says so.
    """
    data = json.loads(real_site.read(site.SITE_SEARCH))
    ids = {}
    for page in data["pages"]:
        rel = "%s/index.html" % page["url"]
        ids[page["url"]] = set(re.findall(r'\bid="([^"]+)"', real_site.read(rel)))
    seen = set()
    for at, anchor, heading, line in data["records"]:
        url = data["pages"][at]["url"]
        assert anchor, "a record of /%s/ has no jump target: %r" % (url, line[:60])
        assert anchor in ids[url], \
            "/%s/ carries no id %r (heading %r)" % (url, anchor, heading)
        seen.add((url, anchor))
    assert len(seen) > 60, len(seen)
    # Proof that the conversion happened at all: the wiki's own records name
    # anchors for the same page that the site's page does not carry
    wiki = site.search_records("rizin.md", "Rizin", _read("docs", "rizin.md"))
    scoped = set(r["h"] for r in wiki) - set([site.page_id("rizin.md")])
    assert scoped, "search_records no longer names the wiki's scoped anchors"
    assert not (scoped & ids["rizin"]), \
        "the wiki's anchors are ids of the site's page too, so this proves nothing"
    # Every `##` heading of a page is a target of the index, and the words of
    # the heading are the ones the index shows
    heads = {}
    for at, anchor, heading, line in data["records"]:
        heads[(data["pages"][at]["url"], anchor)] = heading
    for page in data["pages"]:
        html = real_site.read("%s/index.html" % page["url"])
        for level, hid, text in site.headings(html):
            if level != 2:
                continue
            assert (page["url"], hid) in heads, \
                "/%s/#%s (%s) is in no record of the index" % (page["url"], hid, text)
            assert heads[(page["url"], hid)] == text, \
                "%s: %r vs %r" % (hid, heads[(page["url"], hid)], text)


def test_two_headings_with_the_same_words_keep_their_own_targets(tmp_path):
    """The second "## Limits" of a page is "limits-2", and the index agrees.

    The renderer numbers a repeated heading with a counter, so an index that
    slugs the words again would send every line of the second section to the
    first one. Round 1: the twins have to be held **adjacent** as well - with
    another heading between them a walk that only watches for the heading to
    change still gets it right, so that arrangement pins the case that works
    while the reader of the second section is dropped on the first.
    """
    page = ("# Rizin\n\n## Limits\n\nThe first limit of the tool.\n\n"
            "## Sessions\n\nA session holds the file open.\n\n"
            "## Limits\n\nThe second limit of the tool.\n")
    built = _fixture_site(tmp_path, {"rizin.md": page})
    data = json.loads(built.read(site.SITE_SEARCH))
    html = built.read("rizin/index.html")
    assert 'id="limits"' in html and 'id="limits-2"' in html
    at = [p["url"] for p in data["pages"]].index("rizin")
    found = dict((r[3], (r[1], r[2])) for r in data["records"] if r[0] == at)
    assert found["The first limit of the tool."] == ("limits", "Limits")
    assert found["The second limit of the tool."] == ("limits-2", "Limits")
    assert found["A session holds the file open."] == ("sessions", "Sessions")

    # The twins with nothing between them, which is the harder half: the lines
    # of the second section have to reach the second id
    twins = ("# Hostile\n\n## Limits\n\nThe first limit of the tool.\n\n"
             "## Limits\n\nThe second limit of the tool.\n\n"
             "## Limits\n\nThe third limit of the tool.\n")
    built = _fixture_site(tmp_path, {"hostile.md": twins}, out="twins")
    data = json.loads(built.read(site.SITE_SEARCH))
    html = built.read("hostile/index.html")
    for anchor in ('id="limits"', 'id="limits-2"', 'id="limits-3"'):
        assert anchor in html, anchor
    at = [p["url"] for p in data["pages"]].index("hostile")
    found = dict((r[3], (r[1], r[2])) for r in data["records"] if r[0] == at)
    assert found["The first limit of the tool."] == ("limits", "Limits")
    assert found["The second limit of the tool."] == ("limits-2", "Limits")
    assert found["The third limit of the tool."] == ("limits-3", "Limits")


def test_a_heading_inside_a_fence_is_no_section_of_the_index(tmp_path):
    """A `##` inside a fenced block is a comment, in the index as in the page.

    The guide's blocks are full of them (`## the firewall rules`), and a walk
    that read one as a heading would file the lines after it under a section
    that is nowhere on the page.
    """
    page = ("# Logs\n\n## Queries\n\nA query reads the log.\n\n"
            "```bash\n## not a heading, a comment\necho hello\n```\n\n"
            "A line after the block.\n\n## Fields\n\nA field is a column.\n")
    built = _fixture_site(tmp_path, {"logs.md": page})
    data = json.loads(built.read(site.SITE_SEARCH))
    html = built.read("logs/index.html")
    ids = set(re.findall(r'\bid="([^"]+)"', html))
    assert "not-a-heading-a-comment" not in ids
    at = [p["url"] for p in data["pages"]].index("logs")
    found = dict((r[3], (r[1], r[2])) for r in data["records"] if r[0] == at)
    assert found["A query reads the log."] == ("queries", "Queries")
    assert found["## not a heading, a comment"] == ("queries", "Queries")
    assert found["A line after the block."] == ("queries", "Queries")
    assert found["A field is a column."] == ("fields", "Fields")
    for anchor, _ in found.values():
        assert anchor in ids, anchor


def test_a_section_the_page_does_not_carry_stops_the_build(tmp_path):
    """A heading of the markdown that is no id of the written page is refused.

    The index and the page come out of the same render, so this cannot happen
    from a docs page today - and if a later change to the renderer or to
    `search_records` made the two disagree, the wrong answer is a hit that
    lands somewhere else without a word. So it is a build error, not a guess.
    """
    page = {"name": "rizin.md", "url": "rizin", "title": "Rizin",
            "text": "# Rizin\n\n## Limits\n\nA line under the limits.\n",
            "headings": [(1, "rizin", "Rizin")]}   # the h2 is missing from the page
    with pytest.raises(site.WikiError) as err:
        site.site_records(page)
    message = str(err.value)
    assert "rizin.md" in message and "Limits" in message, message
    assert "limits" in message, message
    # With the heading the page really carries, the same call answers
    page["headings"].append((2, "limits", "Limits"))
    assert site.site_records(page) == [("limits", "Limits", "A line under the limits.")]


def test_the_index_is_fetched_not_inlined(real_site):
    """No page carries the index; the script fetches it from this site.

    A copy of 200 KB of JSON in every page would be the same index as many
    times over - and the index of a page's own text, which the page already
    is. A fetch of a file of this site is not a request to the outside.
    """
    raw = real_site.read(site.SITE_SEARCH)
    data = json.loads(raw)
    middle = json.dumps(data["records"][len(data["records"]) // 2],
                        ensure_ascii=False, separators=(",", ":"))
    for rel in real_site.pages():
        html = real_site.read(rel)
        assert '"records"' not in html, rel
        assert middle not in html, rel
        assert len(html) < 100000, "%s is %d bytes" % (rel, len(html))
    js = real_site.read(site.SITE_SCRIPT)
    assert site.SITE_SEARCH in js, "assets/site.js does not name the index"
    assert "fetch(" in js, "assets/site.js does not fetch anything"
    # Relative, and from this site: not from the server's root (the site lives
    # under a sub-path) and not from anywhere else
    assert "/%s" % site.SITE_SEARCH not in js, "site.js asks for the index from the root"
    assert "http://" not in js and "https://" not in js
    # Every page says where the root of the site is, relatively
    for rel in real_site.pages():
        root = re.search(r'data-root="([^"]*)"', real_site.read(rel))
        assert root, "%s does not say where the root is" % rel
        assert root.group(1) == ("./" if rel == "index.html" else "../"), \
            "%s: %s" % (rel, root.group(1))


@needs_node
def test_the_search_shows_the_page_the_heading_and_the_line(real_site):
    """What the reader sees: the page, the heading, the line, the words marked.

    The whole way through, in a browser: the field takes the word, the script
    fetches the index of the built site, and the hit it builds carries the
    page's name, the heading beneath it and the line under that, with the
    match in a <mark> - and its link is the address of that section.

    Round 1 takes in the three things the brief named and no test held: the
    search is case-blind, the count line says how many there are, and a long
    line is shown with its words on **both** sides of the match.
    """
    out = _run_site_js(r"""
      (async function () {
        await typed('h');
        var one = { fetched: fetched.slice(), shown: shown() };
        await typed('hexdump');
        var hit = { fetched: fetched.slice(), shown: shown() };
        await typed('HexDump');
        var shouted = shown();
        await typed('zzzznothinghere');
        var none = shown();
        await typed('x'.repeat(300));
        var long = shown();
        await typed('console without a shell');
        var head = shown();
        await typed('named pipe');
        var many = shown();
        console.log(JSON.stringify({ one: one, hit: hit, shouted: shouted, none: none,
                                     long: long, head: head, many: many }));
      })();
    """, real_site.read(site.SITE_SEARCH), _shipped(real_site))
    # One character is not a search: nothing is fetched and nothing is shown
    assert out["one"]["fetched"] == []
    assert out["one"]["shown"]["hidden"] is True
    assert out["one"]["shown"]["expanded"] in (None, "false")
    # The word of the deep page: fetched once, from this site
    assert out["hit"]["fetched"] == ["../search.json"]
    shown = out["hit"]["shown"]
    assert shown["hidden"] is False and shown["expanded"] == "true"
    assert shown["hits"], shown
    first = shown["hits"][0]
    assert first["tag"] == "A"
    assert first["href"] == "../rizin/#console-without-a-shell", first["href"]
    assert first["role"] == "option" and first["id"] == "hit-0"
    page, heading, line = first["parts"]
    assert page["cls"] == "hit-page" and page["text"] == "Rizin"
    assert heading["cls"] == "hit-head" and heading["text"] == "Console without a shell"
    assert line["cls"] == "hit-line"
    assert line["marks"] == ["hexdump"], line
    assert "hexdump" in line["text"]
    assert set(line["tags"]) <= {"#text", "MARK"}, line["tags"]
    # The count says what it counted, in words
    assert shown["note"] == "1 hit", shown["note"]
    # A long line is shown around its match, not up to it: the words before
    # and the words after, each ending in an ellipsis
    assert line["tags"] == ["#text", "MARK", "#text"], line["tags"]
    lead, _, tail = line["texts"]
    assert len(lead) > 20 and lead.startswith("\u2026"), repr(lead)
    assert len(tail) > 20 and tail.endswith("\u2026"), repr(tail)
    # Upper case finds the same line, and the mark keeps the text's own case
    assert [h["href"] for h in out["shouted"]["hits"]] == [first["href"]]
    assert out["shouted"]["hits"][0]["parts"][2]["marks"] == ["hexdump"]
    assert out["shouted"]["note"] == "1 hit"
    # A word that is nowhere says so, and shows no hit
    assert out["none"]["hits"] == []
    assert out["none"]["hidden"] is False
    assert "zzzznothinghere" in out["none"]["note"], out["none"]["note"]
    # ... and a term longer than the box is cut, so the line cannot run out of it
    assert len(out["long"]["note"]) < 100, len(out["long"]["note"])
    assert out["long"]["note"].endswith("\u2026\u201d"), out["long"]["note"]
    # A heading searched for brings its own section first
    assert out["head"]["hits"], out["head"]
    assert out["head"]["hits"][0]["href"] == "../rizin/#console-without-a-shell"
    # More hits than are shown: the count says both numbers
    assert len(out["many"]["hits"]) == 40, len(out["many"]["hits"])
    assert re.match(r"^40 of \d\d+ hits$", out["many"]["note"]), out["many"]["note"]


@needs_node
def test_a_hit_is_text_and_never_markup(real_site):
    """A line of a docs page is text, in the page and in a hit.

    The guide writes about `<script>` and about `onerror=`; a search that put
    its hits into the page as markup would run them under the repository's own
    origin, where the site is published.
    """
    js = _shipped(real_site)
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                      "createContextualFragment"):
        assert forbidden not in js, "assets/site.js writes markup: %s" % forbidden
    out = _run_site_js(r"""
      (async function () {
        await typed('onerror');
        console.log(JSON.stringify(shown()));
      })();
    """, HOSTILE_INDEX, js)
    assert out["hits"], out
    hit = out["hits"][0]
    page, heading, line = hit["parts"]
    # The attack arrives as the text it is: no element was made of it
    assert page["text"] == "<img src=x onerror=alert(1)>"
    assert heading["text"] == "A <script>alert(2)</script> heading"
    assert "<script>alert(3)</script>" in line["text"]
    for part in (page, heading, line):
        assert set(part["tags"]) <= {"#text", "MARK"}, part
    assert line["marks"] == ["onerror"], line


@needs_node
def test_the_index_is_fetched_once_and_a_failure_is_said_out_loud(real_site):
    """The file is fetched when the reader first types, and only then.

    One file per reader, not one per keystroke: the keystrokes that matter are
    the ones while the file is still on its way, when nothing has arrived to
    search in yet - here the answer waits until the test lets it go. And when
    the index cannot be had at all - the site opened from a folder, where
    fetch has no origin - the field says so instead of staying silent.
    """
    out = _run_site_js(r"""
      (async function () {
        await typed('he');
        await typed('hex');
        await typed('hexdu');
        var waiting = { fetched: fetched.slice(), hits: shown().hits.length,
                        hidden: shown().hidden };
        release();
        await flush();
        await flush();
        var arrived = { fetched: fetched.slice(), hits: shown().hits.length,
                        note: shown().note };
        await typed('hexdump');
        console.log(JSON.stringify({ waiting: waiting, arrived: arrived,
                                     all: fetched.slice() }));
      })();
    """, real_site.read(site.SITE_SEARCH), _shipped(real_site), hold=True)
    # Three keystrokes while the file is on its way: one request
    assert out["waiting"]["fetched"] == ["../search.json"], out["waiting"]
    assert out["waiting"]["hits"] == 0
    # When it arrives the word that stands in the field now is the one searched
    assert out["arrived"]["fetched"] == ["../search.json"]
    assert out["arrived"]["hits"] > 0, out["arrived"]
    assert out["all"] == ["../search.json"], out["all"]
    # The front page asks for the file in its own folder
    root = _run_site_js(r"""
      (async function () {
        await typed('onerror');
        console.log(JSON.stringify({ fetched: fetched.slice(),
                                     href: shown().hits[0].href }));
      })();
    """, HOSTILE_INDEX, _shipped(real_site), root="./")
    assert root["fetched"] == ["./search.json"]
    assert root["href"] == "./evil/#shell"
    # A 404 is said, and the next keystroke tries again
    lost = _run_site_js(r"""
      (async function () {
        await typed('onerror');
        var first = shown();
        await typed('onerror lives');
        console.log(JSON.stringify({ first: first, tries: fetched.length }));
      })();
    """, HOSTILE_INDEX, _shipped(real_site), ok=False, status=404)
    assert lost["first"]["hits"] == []
    assert lost["first"]["note"].strip(), "a failed index says nothing at all"
    assert lost["tries"] == 2, lost["tries"]


@needs_node
def test_the_keyboard_works_the_search(real_site):
    """`/` opens it, the arrows walk the hits, Enter follows one, Escape closes.

    The shortcut may not steal the key from a field someone is typing in, and
    Enter has to follow the hit that is marked - not always the first one.
    """
    out = _run_site_js(r"""
      (async function () {
        fireDoc('keydown', { key: '/' });
        var opened = focused.slice();
        fireDoc('keydown', { key: '/', target: field });
        var inField = focused.slice();
        await typed('hexdump');
        var count = shown().hits.length;
        fire(field, 'keydown', { key: 'Enter' });
        var first = went.slice();
        await typed('a session');
        var many = shown().hits.length;
        fire(field, 'keydown', { key: 'ArrowDown' });
        fire(field, 'keydown', { key: 'ArrowDown' });
        var marked = shown().hits.map(function (hit) { return hit.active; });
        var hrefs = shown().hits.map(function (hit) { return hit.href; });
        fire(field, 'keydown', { key: 'Enter' });
        var second = went.slice();
        await typed('hexdump');
        fire(field, 'keydown', { key: 'Escape' });
        var closed = { hidden: shown().hidden, value: field.value, hits: shown().hits.length };
        console.log(JSON.stringify({ opened: opened, inField: inField, count: count,
                                     first: first, many: many, marked: marked,
                                     hrefs: hrefs, second: second, closed: closed }));
      })();
    """, real_site.read(site.SITE_SEARCH), _shipped(real_site))
    assert out["opened"] == ["search"], "/ does not reach the search field"
    assert out["inField"] == ["search"], "/ in a field was taken as a shortcut"
    assert out["count"] == 1, out["count"]
    # Enter with nothing marked follows the first hit
    assert out["first"] == ["../rizin/#console-without-a-shell"], out["first"]
    # The arrows mark the second hit, and Enter follows that one
    assert out["many"] > 2, out["many"]
    assert out["marked"][1] is True, out["marked"]
    assert [i for i, on in enumerate(out["marked"]) if on] == [1], out["marked"]
    assert out["second"][1:] == [out["hrefs"][1]], out["second"]
    assert out["closed"] == {"hidden": True, "value": "", "hits": 0}


@needs_node
def test_a_click_on_a_hit_takes_the_list_with_it(real_site):
    """An ordinary click follows the hit and closes the list; a new tab does not.

    A hit of the page the reader is on is a jump inside it, so nothing
    reloads - and a list left standing would cover the very section he was
    looking for. Cmd-, ctrl-, shift- and middle-click are the browser's own
    way to a new tab and may not be taken away.
    """
    out = _run_site_js(r"""
      (async function () {
        await typed('onerror');
        var hit = hits.children[0];
        fire(hit, 'click', { metaKey: true, button: 0 });
        var newTab = { went: went.slice(), hidden: shown().hidden, prevented: prevented.slice() };
        fire(hit, 'click', { button: 0 });
        var plain = { went: went.slice(), hidden: shown().hidden, prevented: prevented.slice() };
        console.log(JSON.stringify({ newTab: newTab, plain: plain }));
      })();
    """, HOSTILE_INDEX, _shipped(real_site))
    # A new tab: the browser does it, the list stays
    assert out["newTab"]["went"] == [] and out["newTab"]["hidden"] is False
    assert out["newTab"]["prevented"] == []
    # An ordinary click: followed here, and the list is gone
    assert out["plain"]["went"] == ["../evil/#shell"]
    assert out["plain"]["hidden"] is True
    assert out["plain"]["prevented"] == ["click"]


@needs_node
def test_the_search_says_what_it_found_to_a_screen_reader(real_site):
    """The list is a listbox, the count a live region, the marked hit named.

    The hits are links and reachable with Tab, which is the important half;
    without the roles nothing says that a list opened, how many hits there are
    or which of them the arrows are on.
    """
    # The markup, on every page: the field is a combobox over the hit list,
    # and the count is a region of the page, not an element made when a
    # search runs (a live region added with its own text is not announced)
    for rel in real_site.pages():
        html = real_site.read(rel)
        field = re.search(r'<input id="search"[^>]*>', html)
        assert field, rel
        for attr in ('role="combobox"', 'aria-expanded="false"',
                     'aria-controls="search-hits"', 'aria-autocomplete="list"',
                     'aria-label="Search the guide"'):
            assert attr in field.group(0), "%s: %s" % (rel, field.group(0))
        box = html[html.index('<div id="results"'):html.index("</header>")]
        assert 'id="search-count"' in box and 'role="status"' in box, rel
        assert 'aria-live="polite"' in box, rel
        assert 'id="search-hits"' in box and 'role="listbox"' in box, rel
        assert re.search(r'id="search-hits"[^>]*aria-label="[^"]+"', box), rel
    # A long term may not run out of the dropdown: the note breaks the word
    sheet = site._site_style()
    note = sheet[sheet.index(".hit-note {"):sheet.index("}", sheet.index(".hit-note {"))]
    assert "overflow-wrap" in note or "word-break" in note, note
    # And what the state says while the reader works it
    out = _run_site_js(r"""
      (async function () {
        await typed('a session');
        var open = shown();
        fire(field, 'keydown', { key: 'ArrowDown' });
        var first = shown();
        fire(field, 'keydown', { key: 'ArrowDown' });
        var second = shown();
        fire(field, 'keydown', { key: 'Escape' });
        var closed = shown();
        console.log(JSON.stringify({ open: open, first: first, second: second,
                                     closed: closed }));
      })();
    """, real_site.read(site.SITE_SEARCH), _shipped(real_site))
    opened = out["open"]
    assert opened["expanded"] == "true" and opened["current"] is None
    assert opened["note"].endswith("hits"), opened["note"]
    assert [hit["role"] for hit in opened["hits"]][:3] == ["option", "option", "option"]
    assert [hit["id"] for hit in opened["hits"]][:3] == ["hit-0", "hit-1", "hit-2"]
    assert all(hit["selected"] == "false" for hit in opened["hits"])
    # The arrows say which one they are on, to the eye and to a reader
    assert out["first"]["current"] == "hit-0"
    assert [hit["selected"] for hit in out["first"]["hits"]][:2] == ["true", "false"]
    assert out["second"]["current"] == "hit-1"
    assert [hit["selected"] for hit in out["second"]["hits"]][:2] == ["false", "true"]
    # Escape says it is closed and names no hit any more
    assert out["closed"]["expanded"] == "false" and out["closed"]["current"] is None
    assert out["closed"]["note"] == "" and out["closed"]["hits"] == []


# Every way a page can ask a server that is not this one for something, in the
# shapes they take in HTML, CSS and JavaScript. The site may of course fetch
# its own search index (Task 4), so the shapes are tested against http(s), not
# against the words themselves - except the ones that can only mean a third
# party or a loader the site has no use for.
SITE_RESOURCE_SHAPES = [
    (r"@import", "a style sheet import"),
    (r"url\(", "a CSS url()"),
    (r"\bEventSource\b", "an EventSource"),
    (r"sendBeacon", "a beacon"),
    (r"XMLHttpRequest", "an XMLHttpRequest"),
    (r"\bimport\s*\(", "a dynamic import"),
    (r"new\s+Image\b", "an Image loader"),
    (r"new\s+WebSocket\b", "a WebSocket"),
    (r"\.src\s*=", "an assignment to .src"),
    (r"serviceWorker", "a service worker"),
    (r"<(?:iframe|object|embed|audio|video)\b", "an embedded resource"),
    (r'type="module"', "an ES module"),
    (r"https?://[^\s\"']*(?:shields\.io|cdn|unpkg|googleapis|gstatic)", "a third party"),
]


def _own_chrome(html):
    """The document without the guide's own text.

    What is left is what the generator writes itself: head, header, register,
    pager, footer and the scripts. Only the rendered markdown is cut out -
    the guide legitimately writes about `sendBeacon` and about localhost, prose
    and code text, escaped, not resources - and the pager stays in, because its
    links are the generator's own.
    """
    start = html.index('<article class="prose">')
    end = html.index("</article>") + len("</article>")
    return html[:start] + html[end:]


def test_nothing_on_the_site_asks_the_outside_for_anything(real_site):
    """No CDN, no fonts from a foreign server, no badge images.

    A page of the site may link the web in its prose - that is a link a reader
    follows, not a request the page makes. What may not happen is a resource
    loaded from somewhere else when the page opens.
    """
    for rel in real_site.written:
        if rel.endswith(".json"):
            # The one shipped file the scan above cannot read: it is data, not
            # a document, and the ban on http(s) cannot apply to its content -
            # the guide writes `http://<vm-ip>:9000` in its own prose, and the
            # index carries the guide's lines. What has to hold for data is
            # that it stays data: JSON and nothing else, fetched and never
            # loaded as a resource of a page.
            text = real_site.read(rel)
            data = json.loads(text)  # it is JSON, not a script with a callback
            assert isinstance(data, dict) and sorted(data) == ["pages", "records"], rel
            assert text.lstrip()[0] == "{", "%s does not start as JSON" % rel
            for page_rel in real_site.pages():
                html = real_site.read(page_rel)
                for attr, value in re.findall(r'\s(src|srcset|poster|data|href)="([^"]*)"',
                                              html):
                    assert not value.endswith(rel), \
                        "%s loads %s as a resource: %s=%r" % (page_rel, rel, attr, value)
            sheet = real_site.read(site.SITE_STYLE)
            assert rel not in sheet, "the style sheet names %s" % rel
            # In the script it is fetched, and that is the only way it appears
            js = real_site.read(site.SITE_SCRIPT)
            for at in [m.start() for m in re.finditer(re.escape(rel), js)]:
                before = js[max(0, at - 40):at]
                assert "fetch(" in before, \
                    "%s is named outside a fetch: %r" % (rel, js[max(0, at - 40):at + 20])
            continue
        if not rel.endswith((".html", ".css", ".js")):
            continue
        if rel in (site.SITE_MERMAID, site.SITE_WIKI):
            # The offline wiki is shipped for download, not read as part of the
            # site: it is one file with its images as `data:` URIs and its own
            # 1100 lines of tests in tests/test_wiki.py.
            # The Mermaid bundle is third-party minified code, pinned by
            # version and SHA-256: it carries the SVG namespace URL, the word
            # "@import" of its CSS parser and d3's fetch wrapper. Both scans
            # run over our own HTML, CSS and JavaScript.
            continue
        text = real_site.read(rel)
        scanned = _own_chrome(text) if rel.endswith(".html") else text
        for pattern, what in SITE_RESOURCE_SHAPES:
            found = re.search(pattern, scanned)
            assert found is None, "%s carries %s: %r" % (
                rel, what, scanned[max(0, found.start() - 60):found.start() + 60])
        if not rel.endswith(".html"):
            assert "http://" not in text and "https://" not in text, \
                "%s names a URL" % rel
            continue
        # Everything the page loads is a file of this site
        for attr, value in re.findall(r'\s(src|srcset|poster|data)="([^"]*)"', text):
            assert not value.startswith(("http://", "https://", "//")), \
                "%s: %s=%r" % (rel, attr, value[:80])
        for tag in re.findall(r"<link\b[^>]*>", text):
            assert not re.search(r'href="(?:https?:)?//', tag), "%s: %s" % (rel, tag)
        for tag in re.findall(r"<script\b[^>]*>", text):
            assert not re.search(r'src="(?:https?:)?//', tag), "%s: %s" % (rel, tag)
        # An http(s) URL may only stand in a link of the prose or the header
        for attr, value in re.findall(r'\s([a-zA-Z-]+)="([^"]*)"', text):
            if value.startswith(("http://", "https://")):
                assert attr == "href", "%s: %s=%r" % (rel, attr, value[:80])
    # No picture is carried in a page: the website loads each file when it is
    # reached, instead of 12 MB of Base64 per page. The only `data:` on a page
    # is the favicon, which is a handful of bytes of SVG and no request at all.
    for rel in real_site.pages():
        html = real_site.read(rel)
        for kind in ("data:image/png", "data:image/gif", "data:image/jpeg"):
            assert kind not in html, "%s: %s" % (rel, kind)
        for tag in re.findall(r"<[^>]*\bdata:[^>]*>", html):
            assert tag.startswith('<link rel="icon"'), "%s: %s" % (rel, tag[:90])
        assert len(re.findall(r'href="data:', html)) == 1, rel


def test_markdown_cannot_become_live_html_on_the_site(tmp_path):
    """The same defusing as in the wiki, in the output that is published.

    A docs page is text. If a `<script>` in it became an element, the page
    would run it on github.io - under the repository's own origin.
    """
    page = ("# Evil\n\n<script>alert(1)</script>\n\n"
            "<img src=x onerror=alert(2)>\n\n"
            "A [link](javascript:alert(3)) here.\n\n"
            "<a href=\"javascript:alert(5)\">click</a>\n")
    built = _fixture_site(tmp_path, {"evil.md": page})
    html = built.read("evil/index.html")
    content = html[html.index('<main class="content"'):html.index("</main>")]
    assert "<script" not in content, content[:400]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "<img src=x" not in content and "&lt;img src=x onerror=" in content
    assert "onerror=alert(2)&gt;" in content, "the line is not shown as it stands"
    # A link that could run code keeps its text and its URL visible, and is no
    # link at all
    assert 'href="javascript:' not in html and 'src="javascript:' not in html
    assert "link (javascript:alert(3))" in content
    assert "&lt;a href=&quot;javascript:alert(5)&quot;&gt;click&lt;/a&gt;" in content
    # The only scripts on the page are the generator's own
    tags = re.findall(r"<script\b[^>]*>", html)
    assert tags == ['<script src="../assets/site.js" defer>'], tags


# --- The publication ---------------------------------------------------------
#
# The site is built and deployed by .github/workflows/pages.yml on a push to
# main. Nothing here can push to GitHub, so what is held is the shape of that
# file: the target it builds is the one the Makefile has, the folder it uploads
# is the one that target writes, the rights and the queue a deployment needs
# are declared, and no step can swallow a failed build and leave the last good
# site published as if nothing had happened. The spec asks for exactly that -
# a renamed target must not switch the publication off in silence.
#
# The repository installs no YAML parser (standard library only, in the CI as
# well), so the file is read by the small subset below: block maps, block
# sequences, scalars and `|` blocks, which is all a workflow is. It is strict
# about indentation, so a file it reads at all is a file GitHub reads the same
# way.

# The published address, as the spec writes it, stands at the top of this file
# (SITE_URL): the badge test of the front page reads it too.
# Any spelling of a Pages address, with or without its scheme, so a second one
# written half-way (a bare domain, a missing slash) is found too.
PAGES_SPELLING = re.compile(r"(?:https?://)?[\w-]+\.github\.io[^\s)\"'<>,]*")


def _yaml_scalar(text):
    """A value of one line: a quoted string, a flow list, a bool or a word.

    What this subset cannot read it refuses, rather than hand the characters
    back as a word: an anchor, an alias, a tag or a flow map would otherwise
    arrive as the string "&a 1" and quietly pass a check about the value
    behind it.
    """
    text = text.strip()
    if text[:1] in ("'", '"'):
        return text[1:text.index(text[0], 1)]
    text = re.sub(r"\s+#.*$", "", text).strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_yaml_scalar(part) for part in inner.split(",")] if inner else []
    assert not re.match(r"^[&*!{}?\[\]|>]", text), \
        "this subset of YAML does not read %r; write the value out" % text
    if text in ("true", "false"):
        return text == "true"
    return text


def _yaml_skip(lines, i):
    """The next line that carries something; blanks and comments are nothing."""
    while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    return i


def _yaml_node(lines, i, indent):
    """The block at `indent` from line `i` as (value, the line after it)."""
    mapping, items = None, None
    while True:
        i = _yaml_skip(lines, i)
        if i >= len(lines):
            break
        line = lines[i]
        at = len(line) - len(line.lstrip(" "))
        if at < indent:
            break
        assert at == indent, \
            "line %d is indented %d, not %d: %r" % (i + 1, at, indent, line)
        body = line.strip()
        if body == "-" or body.startswith("- "):
            if mapping is not None:
                break               # a list after a key: the map ends here
            items = [] if items is None else items
            rest = body[1:].strip()
            if re.match(r'^(?:"[^"]*"|[\w.$-]+):(?:\s|$)', rest):
                lines[i] = " " * (indent + 2) + rest    # the item is a map
                value, i = _yaml_node(lines, i, indent + 2)
            elif rest:
                value, i = _yaml_scalar(rest), i + 1
            else:
                value, i = _yaml_node(lines, i + 1, indent + 2)
            items.append(value)
            continue
        key = re.match(r'^("[^"]*"|[\w.$-]+):(?:\s+(.*))?$', body)
        assert key, "line %d is neither a key nor a list item: %r" % (i + 1, line)
        if items is not None:
            break                   # a key after a list: the list ends here
        mapping = {} if mapping is None else mapping
        name = _yaml_scalar(key.group(1))
        assert name not in mapping, "line %d: %s stands twice in one map" % (i + 1, name)
        rest = (key.group(2) or "").strip()
        if rest in ("|", "|-", ">", ">-"):
            block, i = [], i + 1
            while i < len(lines) and (not lines[i].strip() or
                                      len(lines[i]) - len(lines[i].lstrip(" ")) > indent):
                block.append(lines[i][indent + 2:] if lines[i].strip() else "")
                i += 1
            joined = "\n".join(block).rstrip()
            mapping[name] = joined if rest.startswith("|") else " ".join(joined.split())
        elif rest:
            mapping[name], i = _yaml_scalar(rest), i + 1
        else:
            j = _yaml_skip(lines, i + 1)
            child = len(lines[j]) - len(lines[j].lstrip(" ")) if j < len(lines) else -1
            assert child > indent or (child == indent and lines[j].strip().startswith("-")), \
                "line %d: %s has no value under it" % (i + 1, name)
            mapping[name], i = _yaml_node(lines, j, child)
    return (mapping if mapping is not None else items), i


def _yaml(text):
    """The subset of YAML a workflow is, as dicts, lists and strings."""
    lines = text.replace("\r\n", "\n").split("\n")
    value, end = _yaml_node(lines, 0, 0)
    assert _yaml_skip(lines, end) == len(lines), \
        "line %d is left over: %r" % (end + 1, lines[end])
    assert isinstance(value, dict) and value, "the workflow is not a mapping"
    return value


def _yaml_walk(node, path=""):
    """Every key and every value of a parsed workflow, with where it stands."""
    if isinstance(node, dict):
        for name, value in node.items():
            here = "%s.%s" % (path, name) if path else str(name)
            yield here, name, value
            for found in _yaml_walk(value, here):
                yield found
    elif isinstance(node, list):
        for n, value in enumerate(node):
            here = "%s[%d]" % (path, n)
            yield here, None, value
            for found in _yaml_walk(value, here):
                yield found


def _yaml_swallows(workflow):
    """What in a parsed workflow would let a failed build pass for a green run.

    Read off the parsed values, not the file: the file may well explain both of
    these words in a comment, and a comment switches nothing off.
    """
    found = []
    for where, name, value in _yaml_walk(workflow):
        if name == "continue-on-error":
            found.append("%s lets a step fail without failing the run" % where)
        if isinstance(value, str) and "always()" in value:
            found.append("%s runs even after the build failed: %r" % (where, value))
    return found


def test_the_workflow_builds_the_site_and_uploads_it():
    """pages.yml: on a push to main, `make site`, upload, deploy - and no way
    to publish anything but a build that worked.

    Every piece of this is load-bearing and silent when it breaks: a trigger
    that also fires on a branch would publish work in progress, a missing
    right makes deploy-pages fail at the end of a four-minute build, a missing
    concurrency group lets two pushes overtake each other, and one `|| true`
    would turn a failed build into a green run that publishes nothing new.
    """
    text = _read(".github", "workflows", "pages.yml")
    makefile = _read("Makefile")
    workflow = _yaml(text)
    assert workflow["name"], "the workflow has no name"

    # On a push to main, and on nothing else: the site is what main says
    assert list(workflow["on"]) == ["push"], sorted(workflow["on"])
    assert workflow["on"]["push"]["branches"] == ["main"], workflow["on"]["push"]

    # The rights a deployment needs: the OIDC token deploy-pages exchanges and
    # the right to publish. Nothing may write to the repository.
    rights = workflow["permissions"]
    assert rights.get("pages") == "write", rights
    assert rights.get("id-token") == "write", rights
    assert rights.get("contents", "read") == "read", rights
    for name, value in rights.items():
        assert name in ("pages", "id-token", "contents"), \
            "the workflow asks for %s: %s, which publishing does not need" % (name, value)

    # One deployment at a time, and the later push waits instead of overtaking:
    # a cancelled deployment is a site half-published.
    queue = workflow["concurrency"]
    assert queue.get("group"), queue
    assert queue.get("cancel-in-progress") is False, \
        "a cancelled deployment can leave the site half-published: %s" % queue

    # One job: the build hands the artifact straight to the deployment, so
    # there is nothing to coordinate between two of them (a split into build
    # and deploy would need `needs:`, and this test to be told about it).
    assert len(workflow["jobs"]) == 1, sorted(workflow["jobs"])
    job = list(workflow["jobs"].values())[0]
    assert job["runs-on"].startswith("ubuntu-"), job["runs-on"]
    # A limit on the run: without one a hung step holds the concurrency group,
    # and with it every later push, for GitHub's default six hours
    limit = int(job["timeout-minutes"])
    assert 1 <= limit <= 60, "the job's timeout is %d minutes" % limit
    # The environment is what makes the deployment appear as the Pages one, and
    # what puts the published address in the run's summary
    assert job["environment"]["name"] == "github-pages", job["environment"]
    assert re.match(r"^\$\{\{\s*steps\.(\w+)\.outputs\.page_url\s*\}\}$",
                    job["environment"]["url"]), job["environment"]
    deploy_id = re.match(r"^\$\{\{\s*steps\.(\w+)\.outputs\.page_url\s*\}\}$",
                         job["environment"]["url"]).group(1)

    steps = job["steps"]
    order = {}
    for n, step in enumerate(steps):
        action = step.get("uses", "").split("@")[0]
        if not action:
            continue
        assert action not in order, "%s is used twice" % action
        order[action] = n
        name, _, ref = step["uses"].partition("@")
        # Only GitHub's own actions, pinned to a major: a third-party action
        # would run with the right to publish this repository
        assert name.startswith("actions/"), "a third-party action: %s" % step["uses"]
        assert re.match(r"^v\d+$", ref), "%s is not pinned to a major" % step["uses"]
    for action in ("actions/checkout", "actions/setup-python",
                   "actions/configure-pages", "actions/upload-pages-artifact",
                   "actions/deploy-pages"):
        assert action in order, "the workflow does not use %s" % action
    # Pages is switched on, source "GitHub Actions": configure-pages only reads
    # those settings here, it does not turn anything on - `enablement` would
    # ask for rights the run's own token does not have
    for step in steps:
        assert "enablement" not in step.get("with", {}), \
            "Pages is switched on already; the workflow does not switch it on"
    assert steps[order["actions/deploy-pages"]].get("id") == deploy_id, \
        "the environment reads the page_url of a step that is not the deployment"
    assert steps[order["actions/setup-python"]]["with"]["python-version"] == "3.12", \
        steps[order["actions/setup-python"]]

    # One step builds, and it is the Makefile's own target: a renamed target
    # must not switch the publication off in silence
    builds = [n for n, step in enumerate(steps) if "make" in str(step.get("run", ""))]
    assert len(builds) == 1, \
        "%d steps of the workflow run make; one step builds the site" % len(builds)
    run = str(steps[builds[0]]["run"]).strip()
    target = re.match(r"^make\s+([a-z][a-z-]*)$", run)
    assert target, "the build step runs %r, which is not a plain make target" % run
    assert re.search(r"^\.PHONY: %s$" % re.escape(target.group(1)), makefile, re.M), \
        "the workflow runs `%s`, which the Makefile does not have" % run
    assert re.search(r"^%s: docs$" % re.escape(target.group(1)), makefile, re.M), \
        "`%s` does not build the offline wiki the site offers for download" % run

    # ... and what is uploaded is the folder that target writes
    folder = steps[order["actions/upload-pages-artifact"]]["with"]["path"]
    site_dir = re.search(r"^SITE_DIR\s*\?=\s*(\S+)$", makefile, re.M).group(1)
    assert str(folder).strip("/") == site_dir, \
        "the workflow uploads %r, the build writes %s/" % (folder, site_dir)

    # Build, then upload, then deploy - and the checkout and the interpreter
    # before all of it
    assert order["actions/checkout"] < order["actions/setup-python"] < builds[0], order
    assert order["actions/configure-pages"] < order["actions/upload-pages-artifact"], order
    assert builds[0] < order["actions/upload-pages-artifact"] \
        < order["actions/deploy-pages"], order

    # Nothing swallows a failure: a build that stops on a missing picture or a
    # wrong Mermaid checksum has to stop the run with it
    swallowed = _yaml_swallows(workflow)
    assert not swallowed, swallowed
    for step in steps:
        body = str(step.get("run", ""))
        for swallow in ("|| true", "|| :", "|| exit 0", "|| echo", "; true", "set +e"):
            assert swallow not in body, "%r would hide a failed build: %r" % (swallow, body)
        assert not re.search(r"(?:^|\s)make\s+(?:-\S*k|--keep-going)", body), \
            "make would keep going after a failed step: %r" % body

    # The checks stay in tests.yml and the publication here: one file each
    checks = _read(".github", "workflows", "tests.yml")
    for action in ("upload-pages-artifact", "deploy-pages", "configure-pages"):
        assert action not in checks, "tests.yml publishes too (%s)" % action


def test_the_workflow_is_read_or_refused_never_guessed():
    """The subset parser above reads what a workflow is and says no to the
    rest, and the no-swallowing check reads values rather than the file.

    A reading tool that guesses is worse than none: `x: &a 1` handed back as
    the string "&a 1" would make every assertion about x pass for the wrong
    reason, and that is the shape of a check that silently stops checking.
    """
    # What a workflow is, it reads
    assert _yaml("a: 1\nb:\n  - x\n  - y: 'z'\nc: |\n  one\n  two\n") == \
        {"a": "1", "b": ["x", {"y": "z"}], "c": "one\ntwo"}
    assert _yaml("a: [1, 2]\nb: false\n") == {"a": ["1", "2"], "b": False}
    # ... and what it does not, it refuses by name
    for text in ("a: &anchor 1\n", "a: *anchor\n", "a: !!str 1\n",
                 "a: {b: 1}\n", "a: |+\n  x\n"):
        with pytest.raises(AssertionError) as refused:
            _yaml(text)
        assert "does not read" in str(refused.value), text

    # The words that would switch the publication off are read off the values,
    # so the file may explain them in a comment
    assert _yaml_swallows(
        _yaml("jobs:\n  b:\n    # not continue-on-error, and no always()\n"
              "    steps:\n      - run: make site\n")) == []
    for bad in ("jobs:\n  b:\n    steps:\n      - run: make site\n"
                "        continue-on-error: true\n",
                "jobs:\n  b:\n    steps:\n      - run: make site\n"
                "        if: always()\n",
                "jobs:\n  b:\n    continue-on-error: true\n"
                "    steps:\n      - run: make site\n"):
        assert _yaml_swallows(_yaml(bad)), bad


def test_the_readme_and_the_index_link_the_site():
    """The way to the published site: a badge and a line in the README, a line
    in the guide's own index - and one spelling of the address everywhere.

    The site is a way to the manual, not a new product: three mentions, each
    where a reader already looks for the documentation. Two spellings of the
    address would mean one of them is wrong the day the repository is renamed.
    """
    readme = _read("README.md")
    index = _read("docs", "README.md")

    # The badge in the head, beside the existing ones, as one of them
    head = readme[:readme.index("## What it does")]
    badge = re.search(r'<a href="%s"><img src="https://img\.shields\.io[^"]*"'
                      r' alt="([^"]+)"></a>' % re.escape(SITE_URL), head)
    assert badge, "no badge in the README's head links the site"
    assert badge.group(1).strip(), "the badge has no label, so the site has no chip"

    # A line in the documentation section, above the table of pages
    section = readme[readme.index("## Documentation"):]
    section = section[:section.index("\n## ", 1)]
    assert re.search(r"\]\(%s\)" % re.escape(SITE_URL), section), \
        "the documentation section does not link the site"
    assert section.index(SITE_URL) < section.index("| Page |"), \
        "the line stands below the table of pages, not above it"

    # ... and a line in the first paragraph of the guide's index
    paragraph = []
    for line in index.splitlines()[1:]:
        if line.strip():
            paragraph.append(line.strip())
        elif paragraph:
            break
    first = " ".join(paragraph)
    assert re.search(r"\]\(%s\)" % re.escape(SITE_URL), first), \
        "the first paragraph of docs/README.md does not link the site: %r" % first

    # One address, one spelling: every Pages address written anywhere a reader
    # is sent from is this one. docs/superpowers/ is design material and is
    # never published, so it is not read here.
    files = ["README.md", "Makefile", "make.ps1",
             os.path.join(".github", "workflows", "pages.yml"),
             os.path.join("scripts", "build-wiki.py")]
    files += [os.path.join("docs", page) for page in sorted(os.listdir(DOCS))
              if page.endswith(".md")]
    seen = 0
    for rel in files:
        for found in PAGES_SPELLING.findall(_read(rel)):
            assert found == SITE_URL, \
                "%s spells the address %r; everywhere it is %s" % (rel, found, SITE_URL)
            seen += 1
    assert seen >= 3, "the address stands in %d places, and three link it" % seen

    # And on the site itself: the badge is a chip that leads there, and the
    # line of the documentation section is a link of the prose
    html = _front_page()
    assert '<a class="chip" href="%s">%s</a>' % (SITE_URL, badge.group(1)) in html, \
        "the badge is no chip on the front page"
    assert '<a href="%s" target="_blank" rel="noopener">' % SITE_URL in html, \
        "the line of the documentation section is no link on the front page"
