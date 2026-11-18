"""Own dashboards: the store behind webui/dashboards.json and its seven routes.

Nothing is computed here or on the server: a tile is a saved search, and the
browser fetches its numbers from /api/logs/search. So these tests only cover the
store (round trip, every limit, a broken file, a write that fails) and the shapes
the routes answer with, including every error the UI has to show.
"""

import json
import logging
import os
import re
import threading
import time

import pytest

import dashboards

D_ID = re.compile(r"^d-[0-9a-f]{12}$")
P_ID = re.compile(r"^p-[0-9a-f]{12}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

QUERY = "source=firewall action=DROP | top dst_port"


def _store(tmp_path, name="dashboards.json"):
    return dashboards.DashboardStore(str(tmp_path / name))


# ---- the store -------------------------------------------------------------------------------


def test_a_dashboard_and_its_panels_round_trip(tmp_path):
    path = tmp_path / "dashboards.json"
    store = dashboards.DashboardStore(str(path))
    assert store.all() == []

    board = store.add("Beacon hunt")
    assert D_ID.match(board["id"]) and STAMP.match(board["created"])
    assert board["name"] == "Beacon hunt" and board["panels"] == []

    ports = store.add_panel(board["id"], "Dropped ports", QUERY, "pie", "-24h", "")
    hosts = store.add_panel(board["id"], "Hosts", "* | stats count by host", "table", "", "now")
    assert P_ID.match(ports["id"]) and P_ID.match(hosts["id"]) and ports["id"] != hosts["id"]
    assert set(ports) == {"id", "name", "query", "form", "earliest", "latest", "created"}
    assert ports["query"] == QUERY and ports["form"] == "pie"
    assert ports["earliest"] == "-24h" and ports["latest"] == ""
    assert hosts["earliest"] == "" and hosts["latest"] == "now" and STAMP.match(hosts["created"])

    renamed = store.rename(board["id"], "Beacons")
    assert renamed["id"] == board["id"] and renamed["name"] == "Beacons"

    moved = store.update_panel(board["id"], hosts["id"], move="up")
    assert moved["id"] == hosts["id"]
    assert [p["id"] for p in store.all()[0]["panels"]] == [hosts["id"], ports["id"]]
    # at the top 'up' is a no-op, at the bottom 'down' is one
    store.update_panel(board["id"], hosts["id"], move="up")
    store.update_panel(board["id"], ports["id"], move="down")
    assert [p["id"] for p in store.all()[0]["panels"]] == [hosts["id"], ports["id"]]
    store.update_panel(board["id"], hosts["id"], move="down")
    assert [p["id"] for p in store.all()[0]["panels"]] == [ports["id"], hosts["id"]]

    changed = store.update_panel(board["id"], ports["id"], name="Ports", form="bars")
    assert changed["name"] == "Ports" and changed["form"] == "bars" and changed["query"] == QUERY

    # a new store on the same file reads exactly the same, and the ids did not move
    again = dashboards.DashboardStore(str(path)).all()
    assert again == store.all()
    assert again[0]["id"] == board["id"] and again[0]["name"] == "Beacons"
    assert [(p["id"], p["name"], p["form"]) for p in again[0]["panels"]] == [
        (ports["id"], "Ports", "bars"), (hosts["id"], "Hosts", "table")]

    store.remove_panel(board["id"], hosts["id"])
    assert [p["id"] for p in store.all()[0]["panels"]] == [ports["id"]]
    assert store.remove_panel(board["id"], ports["id"]) is None
    assert store.all()[0]["panels"] == []

    assert store.remove(board["id"]) is None
    assert store.all() == [] and dashboards.DashboardStore(str(path)).all() == []


def test_all_hands_out_copies(tmp_path):
    store = _store(tmp_path)
    board = store.add("Keep")
    store.add_panel(board["id"], "Ports", QUERY, "pie", "-24h", "")
    snapshot = store.all()
    snapshot[0]["name"] = "changed"
    snapshot[0]["panels"][0]["form"] = "sankey"
    snapshot[0]["panels"].append({"id": "p-aaaaaaaaaaaa"})
    assert store.all()[0]["name"] == "Keep"
    assert [p["form"] for p in store.all()[0]["panels"]] == ["pie"]


def test_two_dashboards_may_share_a_name_and_the_id_is_the_key(tmp_path):
    store = _store(tmp_path)
    first, second = store.add("Same"), store.add("Same")
    assert first["id"] != second["id"]
    store.remove(first["id"])
    assert [d["id"] for d in store.all()] == [second["id"]]


def test_every_limit_and_every_bad_value_is_refused(tmp_path):
    path = tmp_path / "dashboards.json"
    store = dashboards.DashboardStore(str(path))
    assert issubclass(dashboards.LimitReached, dashboards.Invalid)
    assert dashboards.MAX_DASHBOARDS == 10 and dashboards.MAX_PANELS == 12
    assert dashboards.MAX_NAME == 60 and dashboards.MAX_QUERY == 4000 and dashboards.MAX_TIME == 40
    assert dashboards.FORMS == ("table", "pie", "bars", "line", "sankey")

    boards = [store.add("board %d" % i) for i in range(dashboards.MAX_DASHBOARDS)]
    with pytest.raises(dashboards.LimitReached):
        store.add("one too many")
    did, other = boards[0]["id"], boards[1]["id"]
    for i in range(dashboards.MAX_PANELS):
        store.add_panel(did, "tile %d" % i, QUERY, "table", "-24h", "")
    with pytest.raises(dashboards.LimitReached):
        store.add_panel(did, "one too many", QUERY, "table", "-24h", "")
    pid = store.all()[0]["panels"][0]["id"]

    before = path.read_text(encoding="utf-8")

    for bad in ("", " ", "a" * 61, "a\nb", "a\x00", "a\tb", None, 5, ["a"]):
        with pytest.raises(dashboards.Invalid):
            store.add(bad)
        with pytest.raises(dashboards.Invalid):
            store.rename(did, bad)
        with pytest.raises(dashboards.Invalid):
            store.add_panel(other, bad, QUERY, "table", "", "")
        with pytest.raises(dashboards.Invalid):
            store.update_panel(did, pid, name=bad)

    for bad in ("donut", "", "TABLE", None, 42, ["pie"]):
        with pytest.raises(dashboards.Invalid):
            store.add_panel(other, "tile", QUERY, bad, "", "")
        with pytest.raises(dashboards.Invalid):
            store.update_panel(did, pid, form=bad)

    for bad in ("", "   ", "x" * 4001, None, 7):
        with pytest.raises(dashboards.Invalid):
            store.add_panel(other, "tile", bad, "table", "", "")

    for bad in ("e" * 41, 3, ["-24h"]):
        with pytest.raises(dashboards.Invalid):
            store.add_panel(other, "tile", QUERY, "table", bad, "")
        with pytest.raises(dashboards.Invalid):
            store.add_panel(other, "tile", QUERY, "table", "", bad)

    for bad in ("sideways", "", "UP", 1):
        with pytest.raises(dashboards.Invalid):
            store.update_panel(did, pid, move=bad)
    with pytest.raises(dashboards.Invalid):      # nothing to change
        store.update_panel(did, pid)

    with pytest.raises(dashboards.NotFound):
        store.rename("d-000000000000", "x")
    with pytest.raises(dashboards.NotFound):
        store.remove("d-000000000000")
    with pytest.raises(dashboards.NotFound):
        store.add_panel("d-000000000000", "tile", QUERY, "table", "", "")
    with pytest.raises(dashboards.NotFound):
        store.update_panel(did, "p-000000000000", name="x")
    with pytest.raises(dashboards.NotFound):
        store.remove_panel(did, "p-000000000000")

    assert path.read_text(encoding="utf-8") == before


def test_a_refusal_says_what_was_wrong(tmp_path):
    store = _store(tmp_path)
    board = store.add("  padded  ")
    assert board["name"] == "padded"                     # a name is stripped, not refused
    with pytest.raises(dashboards.Invalid) as bad_name:
        store.add("a" * 61)
    assert "60" in str(bad_name.value) and "name" in str(bad_name.value)
    with pytest.raises(dashboards.Invalid) as bad_form:
        store.add_panel(board["id"], "tile", QUERY, "donut", "", "")
    assert "sankey" in str(bad_form.value) and "form" in str(bad_form.value)
    with pytest.raises(dashboards.NotFound) as gone:
        store.rename("d-000000000000", "x")
    assert str(gone.value) == "Dashboard not found."
    with pytest.raises(dashboards.NotFound) as no_panel:
        store.remove_panel(board["id"], "p-000000000000")
    assert str(no_panel.value) == "Panel not found."


def test_the_time_range_may_be_left_out(tmp_path):
    store = _store(tmp_path)
    board = store.add("Keep")
    panel = store.add_panel(board["id"], "tile", QUERY, "table")
    assert panel["earliest"] == "" and panel["latest"] == ""
    both_none = store.add_panel(board["id"], "tile", QUERY, "table", None, None)
    assert both_none["earliest"] == "" and both_none["latest"] == ""
    fixed = store.add_panel(board["id"], "tile", QUERY, "line",
                            "2026-11-16T09:00:00Z", "2026-11-16T10:00:00Z")
    assert fixed["earliest"] == "2026-11-16T09:00:00Z" and fixed["latest"] == "2026-11-16T10:00:00Z"


GOOD = {"id": "d-0123456789ab", "name": "Keep", "created": "2026-11-16T09:00:00Z",
        "panels": [{"id": "p-0123456789ab", "name": "Ports", "query": QUERY, "form": "pie",
                    "earliest": "-24h", "latest": "", "created": "2026-11-16T09:00:00Z"}]}


def test_a_broken_file_does_not_break_the_store(tmp_path):
    path = tmp_path / "dashboards.json"

    def read(text):
        path.write_text(text, encoding="utf-8")
        return dashboards.DashboardStore(str(path)).all()

    assert read("not json at all") == []
    assert read("") == []
    assert read("{}") == []
    assert read("[]") == []
    assert read('{"dashboards": {"d-0123456789ab": {"name": "x"}}}') == []
    assert read(json.dumps({"dashboards": [GOOD]})[:40]) == []          # cut off halfway
    assert read(json.dumps({"dashboards": [GOOD]})) == [GOOD]

    # a dashboard whose panels are not a list stays, without tiles
    no_list = dict(GOOD, panels={"p-0123456789ab": {"name": "Ports"}})
    assert read(json.dumps({"dashboards": [no_list]})) == [dict(GOOD, panels=[])]

    # one broken record among good ones falls away, the rest is readable
    other = dict(GOOD, id="d-ba9876543210", name="Second", panels=[])
    broken = [
        {"name": "no id", "panels": []},                               # no id
        dict(GOOD, id="nope", panels=[]),                              # id of another shape
        dict(GOOD, id="d-cccccccccccc", name="", panels=[]),           # empty name
        dict(GOOD, id="d-dddddddddddd", name="a\nb", panels=[]),       # control character
        dict(GOOD, id="d-eeeeeeeeeeee", name=42, panels=[]),           # name is not a string
        "a string instead of a record",
        None,
    ]
    assert read(json.dumps({"dashboards": [GOOD] + broken + [other]})) == [GOOD, other]

    # a broken tile falls away, its dashboard and the good tiles stay
    good_panel = GOOD["panels"][0]
    panels = [good_panel,
              dict(good_panel, id="p-111111111111", form=42),
              dict(good_panel, id="p-222222222222", form="donut"),
              dict(good_panel, id="p-333333333333", query=""),
              dict(good_panel, id="p-444444444444", query="x" * 4001),
              dict(good_panel, id="p-555555555555", name="a\x00b"),
              dict(good_panel, id="p-666666666666", latest="l" * 41),
              dict(good_panel, id="p-777777777777", name="Second"),
              {"name": "no id", "query": QUERY, "form": "pie"},
              dict(good_panel, id="p-0123456789ab", name="a duplicate id"),
              "a string instead of a tile"]
    kept = read(json.dumps({"dashboards": [dict(GOOD, panels=panels)]}))
    assert [p["id"] for p in kept[0]["panels"]] == ["p-0123456789ab", "p-777777777777"]

    # a file over the caps is cut down to them (ids unique across the file)
    many = [dict(GOOD, id="d-%012x" % i,
                 panels=[dict(good_panel, id="p-%06x%06x" % (i, j)) for j in range(20)])
            for i in range(20)]
    cut = read(json.dumps({"dashboards": many}))
    assert len(cut) == dashboards.MAX_DASHBOARDS
    assert all(len(d["panels"]) == dashboards.MAX_PANELS for d in cut)

    # a missing file is no error either, and a write after a broken file works
    missing = tmp_path / "gone.json"
    assert dashboards.DashboardStore(str(missing)).all() == []
    path.write_text("not json at all", encoding="utf-8")
    store = dashboards.DashboardStore(str(path))
    fresh = store.add("After the damage")
    assert [d["id"] for d in store.all()] == [fresh["id"]]


def test_a_deeply_nested_file_is_no_error_either(tmp_path, client, tdc):
    """A hand-written file nested past the decoder's recursion limit raises
    RecursionError, which is no ValueError: it must still read as no dashboards,
    and the route must answer the empty list instead of Flask's HTML 500."""
    path = tmp_path / "nested.json"
    path.write_text("[" * 20000 + "]" * 20000, encoding="utf-8")
    assert dashboards.DashboardStore(str(path)).all() == []

    nested = '{"dashboards": ' + "[" * 20000 + "]" * 20000 + "}"
    path.write_text(nested, encoding="utf-8")
    assert dashboards.DashboardStore(str(path)).all() == []

    tdc.set_dashboard_store(dashboards.DashboardStore(str(path)))
    answer = client.get("/api/dashboards")
    assert answer.status_code == 200 and answer.get_json() == {"dashboards": []}


def test_a_panel_id_is_unique_across_the_whole_file(tmp_path):
    """Task 6 builds DOM ids from the tile ids, so a hand-written file must not
    leave the same tile id on two dashboards."""
    good_panel = GOOD["panels"][0]
    path = tmp_path / "dashboards.json"
    path.write_text(json.dumps({"dashboards": [
        GOOD,
        dict(GOOD, id="d-ba9876543210", name="Second",
             panels=[good_panel, dict(good_panel, id="p-777777777777", name="Own")]),
    ]}), encoding="utf-8")
    boards = dashboards.DashboardStore(str(path)).all()
    assert [p["id"] for p in boards[0]["panels"]] == ["p-0123456789ab"]
    assert [p["id"] for p in boards[1]["panels"]] == ["p-777777777777"]
    ids = [p["id"] for d in boards for p in d["panels"]]
    assert len(ids) == len(set(ids))


def test_new_ids_avoid_the_ones_already_in_the_file(tmp_path, monkeypatch):
    """Both id generators ask for another id while the one drawn is taken, and a
    tile id is checked against the tiles of every dashboard."""
    store = _store(tmp_path)
    first = store.add("First")
    second = store.add("Second")
    panel = store.add_panel(first["id"], "tile", QUERY, "table")

    drawn = [first["id"][2:], second["id"][2:], "ffffffffffff",
             panel["id"][2:], "eeeeeeeeeeee"]

    class OnceTaken:
        hex = ""

        def __init__(self):
            OnceTaken.hex = drawn.pop(0) * 3        # uuid4().hex is 32 characters

    monkeypatch.setattr(dashboards.uuid, "uuid4", OnceTaken)
    assert store.add("Third")["id"] == "d-ffffffffffff"
    assert store.add_panel(second["id"], "tile", QUERY, "table")["id"] == "p-eeeeeeeeeeee"
    assert drawn == []


def test_the_name_limit_counts_characters_not_bytes(tmp_path):
    """60 CJK characters are 180 bytes in UTF-8; the limit is 60 characters."""
    store = _store(tmp_path)
    cjk = "\u4e2d" * dashboards.MAX_NAME
    emoji = "\U0001f600" * dashboards.MAX_NAME
    assert store.add(cjk)["name"] == cjk
    assert store.add(emoji)["name"] == emoji
    for one_too_long in (cjk + "\u4e2d", emoji + "\U0001f600"):
        with pytest.raises(dashboards.Invalid):
            store.add(one_too_long)
    # and the file reads them back unchanged
    assert [d["name"] for d in dashboards.DashboardStore(store.path).all()] == [cjk, emoji]
    board = store.all()[0]
    assert store.add_panel(board["id"], emoji, QUERY, "table")["name"] == emoji
    with pytest.raises(dashboards.Invalid):
        store.add_panel(board["id"], cjk + "\u4e2d", QUERY, "table")


def test_two_writes_at_the_same_time_both_survive(tmp_path, monkeypatch):
    """What the lock is for: two requests read the list, change it and put the
    file in its place; neither may lose the other's entry. The write is slowed
    down to widen the window a lock-less store would lose an entry in."""
    store = _store(tmp_path)
    real_write = store._write

    def slow_write(records):
        time.sleep(0.05)
        real_write(records)

    monkeypatch.setattr(store, "_write", slow_write)
    failures = []

    def work(call):
        try:
            call()
        except Exception as exc:                    # noqa: BLE001 - reported below
            failures.append(exc)

    names = ["from thread %d" % i for i in range(6)]
    threads = [threading.Thread(target=work, args=(lambda n=n: store.add(n),)) for n in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert failures == []
    assert sorted(d["name"] for d in store.all()) == sorted(names)
    assert len({d["id"] for d in store.all()}) == len(names)

    # the same for tiles of one dashboard
    did = store.all()[0]["id"]
    tiles = ["tile %d" % i for i in range(6)]
    threads = [threading.Thread(target=work, args=(
        lambda n=n: store.add_panel(did, n, QUERY, "table"),)) for n in tiles]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert failures == []
    board = next(d for d in store.all() if d["id"] == did)
    assert sorted(p["name"] for p in board["panels"]) == sorted(tiles)
    assert len({p["id"] for p in board["panels"]}) == len(tiles)


def test_a_failed_write_leaves_the_old_file(tmp_path, monkeypatch):
    path = tmp_path / "dashboards.json"
    store = dashboards.DashboardStore(str(path))
    store.add("Keep")
    before = path.read_text(encoding="utf-8")

    def boom(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.add("Later")
    monkeypatch.undo()
    assert path.read_text(encoding="utf-8") == before
    assert not os.path.exists(str(path) + ".tmp")
    assert [d["name"] for d in store.all()] == ["Keep"]

    # on Windows another program holding the file for a moment is retried
    attempts = []
    real_replace = os.replace

    def busy(src, dst):
        attempts.append(1)
        raise PermissionError(13, "used by another process")

    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    monkeypatch.setattr(os, "replace", busy)
    with pytest.raises(PermissionError):
        store.add("Later")
    assert len(attempts) == 10

    def busy_twice(src, dst):
        attempts.append(1)
        if len(attempts) <= 12:
            raise PermissionError(13, "used by another process")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", busy_twice)
    late = store.add("Later")
    monkeypatch.undo()
    assert not os.path.exists(str(path) + ".tmp")
    assert [d["name"] for d in store.all()] == ["Keep", "Later"]
    assert late["name"] == "Later"


# ---- the routes ------------------------------------------------------------------------------


PANEL_BODY = {"name": "Dropped ports", "query": QUERY, "form": "pie",
              "earliest": "-24h", "latest": ""}


def test_the_routes_answer_the_documented_shapes(client, tdc, tmp_path):
    assert client.get("/api/dashboards").get_json() == {"dashboards": []}

    created = client.post("/api/dashboards", json={"name": "Beacon hunt"})
    assert created.status_code == 201
    board = created.get_json()["dashboard"]
    assert set(board) == {"id", "name", "created", "panels"}
    assert D_ID.match(board["id"]) and board["name"] == "Beacon hunt" and board["panels"] == []

    renamed = client.patch("/api/dashboards/" + board["id"], json={"name": "Beacons"})
    assert renamed.status_code == 200
    assert renamed.get_json()["dashboard"] == dict(board, name="Beacons")

    added = client.post("/api/dashboards/%s/panels" % board["id"], json=PANEL_BODY)
    assert added.status_code == 201
    panel = added.get_json()["panel"]
    assert set(panel) == {"id", "name", "query", "form", "earliest", "latest", "created"}
    assert panel["query"] == QUERY and panel["form"] == "pie" and panel["earliest"] == "-24h"

    # earliest and latest may be left out
    short = client.post("/api/dashboards/%s/panels" % board["id"],
                        json={"name": "Hosts", "query": "* | stats count by host", "form": "table"})
    assert short.status_code == 201
    second = short.get_json()["panel"]
    assert second["earliest"] == "" and second["latest"] == ""

    patched = client.patch("/api/dashboards/%s/panels/%s" % (board["id"], panel["id"]),
                           json={"form": "bars", "name": "Ports"})
    assert patched.status_code == 200
    assert patched.get_json()["panel"] == dict(panel, form="bars", name="Ports")

    moved = client.patch("/api/dashboards/%s/panels/%s" % (board["id"], second["id"]),
                         json={"move": "up"})
    assert moved.status_code == 200 and moved.get_json()["panel"]["id"] == second["id"]
    listed = client.get("/api/dashboards").get_json()["dashboards"]
    assert [p["id"] for p in listed[0]["panels"]] == [second["id"], panel["id"]]

    gone = client.delete("/api/dashboards/%s/panels/%s" % (board["id"], panel["id"]))
    assert gone.status_code == 200 and gone.get_json() == {"deleted": True}
    assert len(client.get("/api/dashboards").get_json()["dashboards"][0]["panels"]) == 1

    dropped = client.delete("/api/dashboards/" + board["id"])
    assert dropped.status_code == 200 and dropped.get_json() == {"deleted": True}
    assert client.get("/api/dashboards").get_json() == {"dashboards": []}


def test_the_routes_refuse_a_body_they_cannot_read(client, tdc):
    board = client.post("/api/dashboards", json={"name": "Beacons"}).get_json()["dashboard"]
    panel = client.post("/api/dashboards/%s/panels" % board["id"],
                        json=PANEL_BODY).get_json()["panel"]
    panel_path = "/api/dashboards/%s/panels/%s" % (board["id"], panel["id"])

    unknown = client.post("/api/dashboards", json={"name": "x", "colour": "red", "size": 2})
    assert unknown.status_code == 400
    error = unknown.get_json()["error"]
    assert "colour" in error and "size" in error and "name" not in error

    for method, path, body, named in (
            ("post", "/api/dashboards", {"nome": "x"}, "nome"),
            ("patch", "/api/dashboards/" + board["id"], {"title": "x"}, "title"),
            ("post", "/api/dashboards/%s/panels" % board["id"],
             dict(PANEL_BODY, limit=1000), "limit"),
            ("patch", panel_path, {"query": "* | stats count"}, "query")):
        answer = getattr(client, method)(path, json=body)
        assert answer.status_code == 400, path
        assert named in answer.get_json()["error"], path

    for body in ("[]", '"a string"', "17", "null", "not json at all", ""):
        answer = client.post("/api/dashboards", data=body, content_type="application/json")
        assert answer.status_code == 400, body
        assert answer.get_json() == {"error": "JSON object body required"}, body

    # a broken limit and a bad value are 400 with the reason
    too_long = client.post("/api/dashboards", json={"name": "a" * 61})
    assert too_long.status_code == 400 and "60" in too_long.get_json()["error"]
    bad_form = client.post("/api/dashboards/%s/panels" % board["id"],
                           json=dict(PANEL_BODY, form="donut"))
    assert bad_form.status_code == 400 and "form" in bad_form.get_json()["error"]
    bad_move = client.patch(panel_path, json={"move": "sideways"})
    assert bad_move.status_code == 400 and "move" in bad_move.get_json()["error"]
    nothing = client.patch(panel_path, json={})
    assert nothing.status_code == 400 and nothing.get_json()["error"]

    for _ in range(dashboards.MAX_DASHBOARDS - 1):
        assert client.post("/api/dashboards", json={"name": "filler"}).status_code == 201
    full = client.post("/api/dashboards", json={"name": "one too many"})
    assert full.status_code == 400 and "10" in full.get_json()["error"]


def test_a_write_against_something_that_is_gone_says_so(client, tdc):
    board = client.post("/api/dashboards", json={"name": "Beacons"}).get_json()["dashboard"]
    panel = client.post("/api/dashboards/%s/panels" % board["id"],
                        json=PANEL_BODY).get_json()["panel"]
    panel_path = "/api/dashboards/%s/panels/%s" % (board["id"], panel["id"])

    # the second browser tab deleted the tile; this one still has it in its list
    assert client.delete(panel_path).status_code == 200
    for method, body in (("patch", {"name": "Ports"}), ("delete", None)):
        answer = getattr(client, method)(panel_path, json=body)
        assert answer.status_code == 404
        assert answer.get_json() == {"error": "Panel not found."}

    # and then it deleted the whole dashboard
    assert client.delete("/api/dashboards/" + board["id"]).status_code == 200
    for method, path, body in (("patch", "/api/dashboards/" + board["id"], {"name": "x"}),
                               ("delete", "/api/dashboards/" + board["id"], None),
                               ("post", "/api/dashboards/%s/panels" % board["id"], PANEL_BODY),
                               ("patch", panel_path, {"name": "Ports"}),
                               ("delete", panel_path, None)):
        answer = getattr(client, method)(path, json=body)
        assert answer.status_code == 404, path
        assert answer.get_json() == {"error": "Dashboard not found."}, path


def test_a_write_that_cannot_be_saved_answers_500(client, tdc, monkeypatch):
    """A real write failure through the route: os.replace fails, so the file keeps
    what it had, no .tmp is left and the analyst gets the documented message."""
    monkeypatch.setitem(tdc.app.config, "PROPAGATE_EXCEPTIONS", False)
    board = client.post("/api/dashboards", json={"name": "Beacons"}).get_json()["dashboard"]
    path = tdc._dashboards.path
    with open(path, encoding="utf-8") as handle:
        before = handle.read()

    def boom(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", boom)
    answer = client.post("/api/dashboards", json={"name": "Later"})
    panel = client.post("/api/dashboards/%s/panels" % board["id"], json=PANEL_BODY)
    monkeypatch.undo()

    for failed in (answer, panel):
        assert failed.status_code == 500
        assert failed.get_json() == {
            "error": "The dashboards could not be saved; see the web UI log."}
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == before
    assert not os.path.exists(path + ".tmp")
    kept = client.get("/api/dashboards").get_json()["dashboards"]
    assert [d["id"] for d in kept] == [board["id"]] and kept[0]["panels"] == []


def test_a_failure_that_is_not_a_failed_save_logs_a_neutral_message(client, tdc, monkeypatch,
                                                                    caplog):
    """A bug in the store (a TypeError, not an OSError) still answers the
    documented 500, but the log must not claim the file could not be saved."""
    monkeypatch.setitem(tdc.app.config, "PROPAGATE_EXCEPTIONS", False)

    def boom(name):
        raise TypeError("a bug in the store")

    monkeypatch.setattr(tdc._dashboards, "add", boom)
    with caplog.at_level(logging.ERROR):
        answer = client.post("/api/dashboards", json={"name": "Beacons"})
    assert answer.status_code == 500
    assert answer.get_json() == {
        "error": "The dashboards could not be saved; see the web UI log."}
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "could not save the dashboards" not in messages, messages
    assert "dashboard write failed" in messages, messages
    assert "TypeError: a bug in the store" in caplog.text


def test_the_write_routes_are_protected(client, tdc, monkeypatch):
    board = client.post("/api/dashboards", json={"name": "Beacons"}).get_json()["dashboard"]
    panel = client.post("/api/dashboards/%s/panels" % board["id"],
                        json=PANEL_BODY).get_json()["panel"]
    writes = (("post", "/api/dashboards", {"name": "x"}),
              ("patch", "/api/dashboards/" + board["id"], {"name": "x"}),
              ("delete", "/api/dashboards/" + board["id"], None),
              ("post", "/api/dashboards/%s/panels" % board["id"], PANEL_BODY),
              ("patch", "/api/dashboards/%s/panels/%s" % (board["id"], panel["id"]),
               {"name": "x"}),
              ("delete", "/api/dashboards/%s/panels/%s" % (board["id"], panel["id"]), None))

    for method, path, body in writes:
        answer = getattr(client, method)(path, json=body,
                                         headers={"Origin": "http://evil.example"})
        assert answer.status_code == 403, path
        assert answer.get_json() == {"error": "Cross-site request rejected"}, path

    class Busy:
        maintenance = True

    monkeypatch.setattr(tdc, "_update_manager", Busy())
    for method, path, body in writes:
        answer = getattr(client, method)(path, json=body)
        assert answer.status_code == 503, path
        assert answer.get_json()["maintenance"] is True, path
    # reading the dashboards stays open while the tools are updated
    assert client.get("/api/dashboards").status_code == 200
    assert len(client.get("/api/dashboards").get_json()["dashboards"]) == 1


def test_the_default_store_is_the_file_next_to_the_app(tdc):
    """The tests get a store of their own (conftest); the default one is the file
    beside app.py, and set_dashboard_store(None) goes back to it."""
    assert tdc.DASHBOARDS_FILE.endswith(os.path.join("webui", "dashboards.json"))
    assert tdc._default_dashboard_store.path == tdc.DASHBOARDS_FILE
    assert tdc._dashboards is not tdc._default_dashboard_store
