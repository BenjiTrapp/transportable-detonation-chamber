"""
Detonation Chamber - Development Server

Enhanced dev server with:
- Flask debug mode (auto-reload on Python changes)
- Live-reload for frontend assets (CSS/JS/HTML) via SSE
- Auto-opens browser on startup
- Mock service endpoints when backend services are unavailable
- Colored console output with file change notifications

Usage:
    python dev_server.py [--no-open] [--port PORT] [--mock]

Requires: flask, watchdog, requests (all in requirements.txt)
"""

import os
import sys
import time
import json
import signal
import argparse
import threading
import webbrowser
from pathlib import Path
from queue import Queue, Empty
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Response, request as flask_request
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# --- Configuration ---
DEV_PORT = int(os.environ.get("WEBUI_PORT", "9000"))
BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# SSE clients waiting for reload signals
_sse_clients: list[Queue] = []
_sse_lock = threading.Lock()


# --- Colors for console ---
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"


def log(msg, color=Colors.WHITE):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DIM}[{ts}]{Colors.RESET} {color}{msg}{Colors.RESET}")


def log_change(event_type, path):
    rel = os.path.relpath(path, BASE_DIR)
    icon = {"modified": "~", "created": "+", "deleted": "-"}.get(event_type, "?")
    color = {"modified": Colors.YELLOW, "created": Colors.GREEN, "deleted": Colors.RED}.get(event_type, Colors.WHITE)
    log(f"{icon} {rel}", color)


# --- SSE Live Reload ---
LIVERELOAD_JS = """
<script id="__dev-livereload">
(function() {
    var es = new EventSource('/__dev/livereload');
    es.onmessage = function(e) {
        var data = JSON.parse(e.data);
        if (data.type === 'reload') {
            console.log('[dev] Reloading...');
            location.reload();
        } else if (data.type === 'css') {
            console.log('[dev] Refreshing CSS...');
            var links = document.querySelectorAll('link[rel="stylesheet"]');
            links.forEach(function(link) {
                var href = link.href.split('?')[0];
                link.href = href + '?v=' + Date.now();
            });
        }
    };
    es.onerror = function() {
        console.log('[dev] Connection lost, retrying...');
    };
})();
</script>
"""


def notify_clients(change_type="reload"):
    """Send reload signal to all connected SSE clients."""
    data = json.dumps({"type": change_type, "time": time.time()})
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(data)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


# --- File Watcher ---
class FrontendChangeHandler(FileSystemEventHandler):
    """Watch for CSS/JS/HTML changes and trigger live-reload."""

    def __init__(self):
        self._debounce = {}
        self._lock = threading.Lock()

    def _should_process(self, path):
        """Debounce: ignore rapid successive events for the same file."""
        now = time.time()
        with self._lock:
            last = self._debounce.get(path, 0)
            if now - last < 0.5:
                return False
            self._debounce[path] = now
        return True

    def _handle(self, event, event_type):
        if event.is_directory:
            return
        path = event.src_path
        ext = os.path.splitext(path)[1].lower()

        # Only watch relevant file types
        if ext not in ('.css', '.js', '.html', '.htm', '.png', '.svg', '.ico'):
            return

        if not self._should_process(path):
            return

        log_change(event_type, path)

        # CSS-only hot update (no full page reload)
        if ext == '.css':
            notify_clients("css")
        else:
            notify_clients("reload")

    def on_modified(self, event):
        self._handle(event, "modified")

    def on_created(self, event):
        self._handle(event, "created")

    def on_deleted(self, event):
        self._handle(event, "deleted")


def start_watcher():
    """Start watchdog observer for static/ and templates/ directories."""
    handler = FrontendChangeHandler()
    observer = Observer()

    watch_dirs = [
        str(STATIC_DIR),
        str(TEMPLATES_DIR),
    ]

    for d in watch_dirs:
        if os.path.exists(d):
            observer.schedule(handler, d, recursive=True)
            log(f"  Watching: {os.path.relpath(d, BASE_DIR)}/", Colors.DIM)

    observer.start()
    return observer


# --- Inject dev tools into Flask app ---
def setup_dev_routes(app):
    """Add development-only routes to the Flask app."""

    @app.route("/__dev/livereload")
    def dev_livereload():
        """SSE endpoint for live-reload notifications."""
        def stream():
            q = Queue()
            with _sse_lock:
                _sse_clients.append(q)
            try:
                # Send initial connected event
                yield f"data: {json.dumps({'type': 'connected'})}\n\n"
                while True:
                    try:
                        data = q.get(timeout=30)
                        yield f"data: {data}\n\n"
                    except Empty:
                        # Keep-alive ping
                        yield f": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                with _sse_lock:
                    if q in _sse_clients:
                        _sse_clients.remove(q)

        return Response(stream(), mimetype="text/event-stream",
                       headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/__dev/status")
    def dev_status():
        """Dev server status endpoint."""
        with _sse_lock:
            client_count = len(_sse_clients)
        return json.dumps({
            "mode": "development",
            "livereload": True,
            "connected_clients": client_count,
            "watched_dirs": ["static/", "templates/"],
        }), 200, {"Content-Type": "application/json"}

    # Inject livereload script into HTML responses
    @app.after_request
    def inject_livereload(response):
        if (response.content_type
                and "text/html" in response.content_type
                and response.status_code == 200):
            data = response.get_data(as_text=True)
            if "</body>" in data:
                data = data.replace("</body>", f"{LIVERELOAD_JS}</body>")
                response.set_data(data)
        return response

    log("  Live-reload: enabled (SSE)", Colors.DIM)


def open_browser(port, delay=1.5):
    """Open browser after a short delay to let the server start."""
    def _open():
        time.sleep(delay)
        url = f"http://localhost:{port}"
        log(f"Opening browser: {url}", Colors.CYAN)
        webbrowser.open(url)
    t = threading.Thread(target=_open, daemon=True)
    t.start()


# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="TDC Development Server")
    parser.add_argument("--port", type=int, default=DEV_PORT,
                       help=f"Port to run on (default: {DEV_PORT})")
    parser.add_argument("--no-open", action="store_true",
                       help="Don't auto-open browser")
    parser.add_argument("--mock", action="store_true",
                       help="Enable mock mode (stub backend APIs)")
    parser.add_argument("--host", default="127.0.0.1",
                       help="Host to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    # Banner
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}  Transportable Detonation Chamber - Dev Server{Colors.RESET}")
    print(f"{Colors.DIM}  ================================================{Colors.RESET}")
    print()

    # Set dev environment
    os.environ["FLASK_DEBUG"] = "1"
    os.environ["FLASK_ENV"] = "development"

    if args.mock:
        os.environ["TDC_MOCK_SERVICES"] = "1"
        log("  Mock mode: ON (backend APIs stubbed)", Colors.YELLOW)

    # Import the app after setting env vars
    from app import app as flask_app

    # Add dev routes
    setup_dev_routes(flask_app)

    # Start file watcher
    observer = start_watcher()

    print()
    log(f"  Server:  http://{args.host}:{args.port}", Colors.GREEN)
    log(f"  Mode:    development (debug + live-reload)", Colors.DIM)
    print()
    print(f"{Colors.DIM}  Changes to CSS/JS/HTML will auto-refresh the browser.{Colors.RESET}")
    print(f"{Colors.DIM}  Changes to Python files will restart the server.{Colors.RESET}")
    print(f"{Colors.DIM}  Press Ctrl+C to stop.{Colors.RESET}")
    print()

    # Auto-open browser
    if not args.no_open:
        open_browser(args.port)

    # Run Flask
    try:
        flask_app.run(
            host=args.host,
            port=args.port,
            debug=True,
            use_reloader=True,
            extra_files=[
                str(STATIC_DIR / "js" / "app.js"),
                str(STATIC_DIR / "css" / "style.css"),
                str(TEMPLATES_DIR / "index.html"),
            ]
        )
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        log("Dev server stopped.", Colors.YELLOW)


if __name__ == "__main__":
    main()
