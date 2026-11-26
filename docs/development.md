# Development

How to run the tests, how to change the code of the Web UI, and what CI checks.

## Tests

```bash
make unit-test        # or: .\make.ps1 unit-test   (no VM needed)
```

`tests/` covers the failure classes fixed so far, so they cannot come back
unnoticed: process instances and PID reuse, attribution of alerts and
processes to a detonation, timestamp handling, persisted memory results,
scanner output parsing, the evidence model and baseline, CSRF / DNS-rebinding
/ write restrictions, proxied content types, XSS (unescaped event fields and
unsafe inline handlers in `app.js`), charts that count other numbers than
their tables and filters, the RIZIN tab (the console allowlist, sessions and
views, against a stand-in for rizin; with a real rizin where one is
installed), MCP tool output, documentation drift (the routes and the MCP
tools against [api.md](api.md), the tab table and the pictures of the README,
the shape of every page of this guide and the numbers the pages quote, in
`tests/test_docs.py`), the offline wiki itself (`tests/test_wiki.py`: the
markdown the generator carries, the navigation, the search index, and that no
resource is loaded over the network) and the documentation website
(`tests/test_site.py`). GitHub Actions runs the suite on every
push (`.github/workflows/tests.yml`). `make test` is different: it submits a
test sample to the running VM.

The wiki's markdown parser carries what the guide uses and no more — headings,
paragraphs, lists, fenced code blocks with a language, inline code, bold,
italic, links, images, tables, blockquotes, rules and fenced `mermaid` blocks.
The eleven forms it deliberately refuses (setext headings, `~~~` fences,
four-space indented code, task-list markers, entity references and the rest)
are listed at the top of `scripts/build-wiki.py`, each with the form to write
instead: read that list before adding a page.

`tests/fake_rizin.py` stands in for rizin's pipe mode, and
`tests/samples/pipesim.c` is a harmless named-pipe sample (build it with
`zig cc`).

## Developer Experience

- **`make deploy-restart`**: Edit locally, push to VM, restart Flask in one command
- **`make run-debug`**: Flask auto-reload on file changes
- **Toast Notifications**: Throttled error/warning/info toasts with 15s dedup
- **Help Modal**: Built-in documentation ("? Help" next to the logo)
- **Tool Updates**: The dashboard checks every VM tool for a newer version and installs updates, one tool or all, while a maintenance mode pauses detonations (see [updates.md](updates.md))
- **Submissions History**: Persisted to JSON with quick hex inspection

The frontend is a single `webui/static/js/app.js` with no build step, so a reload
is all a change needs. `webui/dev_server.py` serves it with live-reload.

## Documentation

This guide lives in `docs/` as Markdown. `make docs` (or `.\make.ps1 docs`) builds
it into one self-contained `webui/static/wiki.html` with navigation, search and
rendered diagrams, which works without a network — on the host and on the VM. The
file is generated, never edited by hand, and the deploy paths upload it when it
exists.

The same pages are also a website: `make site` (or `.\make.ps1 site`) builds
`site/` from the same `docs/*.md` and the README — one address per page, a
search over all of them, and the diagrams drawn — and
`.github/workflows/pages.yml` publishes it on every push to `main`, so changing
a page here publishes it. `make site-serve` serves the build folder locally for
a look before that, and `tests/test_site.py` holds its shape: every page of the
index has an address, every link and every search hit reaches it, and no page
asks anything of a server that is not this one.

**Next:** [Troubleshooting](troubleshooting.md)
