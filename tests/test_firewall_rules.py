"""Enforcement of the FIREWALL tab (webui/firewall_rules.py).

Nothing here touches a firewall: ``FakeRun`` stands in for ``run_powershell``. It speaks the contract of
webui/firewall_rules.ps1 (the ``-Op`` verbs, exit code 3 for "a profile is off", 4 for "the rule is already
there"), so these tests prove the Python side, the order of what it does and what it refuses to claim. What the
script really does to Windows only a VM can show.
"""

import json
import ntpath
import os
import re
import subprocess
import sys

import pytest

import firewall
import firewall_rules as rules_mod

IMAGE = r"C:\x\loader.exe"
PY = r"C:\DetonationChamberUI\venv\Scripts\python.exe"
ALL_ON = {"Domain": True, "Private": True, "Public": True}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeRun:
    """A Windows firewall behind the ``run(args) -> (rc, out, err)`` contract.

    ``timeline`` is shared with ``FakeSettings`` so a test can see what happened before what.
    """

    def __init__(self, profiles=None, outbound="Allow", rule_list=None, get_rule_returns=None, fail=None,
                 fail_once=None, disable_new=False, timeline=None):
        self.calls = []
        self.timeline = timeline if timeline is not None else []
        self.profiles = dict(profiles or ALL_ON)
        self.outbound = {n: outbound for n in self.profiles} if isinstance(outbound, str) else dict(outbound)
        self.rules = {}
        for name in rule_list or ():
            self.rules[name] = self.view(name, Action="Block", Program="Any", RemoteAddress=["Any"],
                                         RemotePort=["Any"], Protocol="Any")
        self.get_rule_returns = get_rule_returns
        self.fail = fail or {}
        self.fail_once = dict(fail_once or {})
        self.disable_new = disable_new
        self.standing = []          # (name, action, program) of every rule, after each call

    @staticmethod
    def view(name, **kw):
        base = {"Name": name, "Enabled": True, "Action": "Block", "Direction": "Outbound", "Profile": "Any",
                "Program": "Any", "RemoteAddress": ["Any"], "RemotePort": ["Any"], "Protocol": "Any"}
        base.update(kw)
        return base

    # -- the contract --

    def __call__(self, args):
        assert isinstance(args, list) and all(isinstance(a, str) for a in args), args
        self.calls.append(list(args))
        if ntpath.basename(args[0]).lower() == "taskkill.exe":
            self.timeline.append(("taskkill", args[2]))
            return self.fail.get("taskkill", (0, "SUCCESS", ""))
        params = self.params(args)
        op = params["Op"]
        self.timeline.append((op, params.get("Name") or params.get("DefaultOutboundAction")))
        if op in self.fail_once:
            rc, err = self.fail_once.pop(op)
            return rc, "", err
        if op in self.fail:
            rc, err = self.fail[op]
            return rc, "", err
        answer = getattr(self, "op_" + op)(params)
        self.standing.append([(n, v["Action"], v["Program"]) for n, v in self.rules.items()])
        return answer

    @staticmethod
    def params(args):
        i = args.index("-File") + 2
        rest = args[i:]
        return {rest[k][1:]: rest[k + 1] for k in range(0, len(rest), 2)}

    def profile_rows(self):
        return [{"Name": n, "Enabled": on, "DefaultOutboundAction": self.outbound.get(n, "Allow")}
                for n, on in self.profiles.items()]

    def off(self):
        return [n for n, on in self.profiles.items() if not on]

    def op_Profiles(self, p):
        return 0, json.dumps(self.profile_rows()), ""

    def op_Enable(self, p):
        self.profiles = {n: True for n in self.profiles}
        return 0, "", ""

    def op_List(self, p):
        return 0, json.dumps({"profiles": self.profile_rows(), "rules": list(self.rules.values())}), ""

    def op_Get(self, p):
        if self.get_rule_returns is not None:
            return 0, self.get_rule_returns, ""
        view = self.rules.get(p["Name"])
        return 0, json.dumps(view) if view else "", ""

    def op_Create(self, p):
        if self.off():
            return 3, "", ", ".join(self.off())
        if p["Name"] in self.rules:
            return 4, "", ""
        self.rules[p["Name"]] = self.view(
            p["Name"], Action=p["Action"], Enabled=not self.disable_new, Program=p.get("Program", "Any"),
            RemoteAddress=p["RemoteAddress"].split(",") if "RemoteAddress" in p else ["Any"],
            RemotePort=[p["RemotePort"]] if "RemotePort" in p else ["Any"], Protocol=p.get("Protocol", "Any"))
        return 0, "", ""

    def op_Remove(self, p):
        self.rules.pop(p["Name"], None)
        return 0, "", ""

    def op_SetDefaultOutbound(self, p):
        names = p["Profiles"].split(",") if "Profiles" in p else list(self.profiles)
        for n in names:
            self.outbound[n] = p["DefaultOutboundAction"]
        return 0, "", ""

    # -- what a test looks at --

    def ops(self):
        return [self.params(c)["Op"] for c in self.calls if c[0] != "taskkill"]

    def writes(self):
        return [o for o in self.ops() if o in ("Create", "Remove", "SetDefaultOutbound", "Enable")]


class FakeSettings:
    def __init__(self, outbound_before=None, isolated=False, isolated_since=None, timeline=None, fail=False):
        self.outbound_before = outbound_before
        self.isolated = isolated
        self.isolated_since = isolated_since
        self.timeline = timeline if timeline is not None else []
        self.fail = fail
        self.saved = []

    def set(self, **changes):
        if self.fail:
            raise OSError("disk full")
        self.timeline.append(("settings", dict(changes)))
        self.saved.append(dict(changes))
        for k, v in changes.items():
            setattr(self, k, v)


def make(**kw):
    timeline = []
    return FakeRun(timeline=timeline, **kw), FakeSettings(timeline=timeline)


SETTINGS = FakeSettings()
FETCHER = "TDC-FW-ISO-fetcher"
LOOPBACK = "TDC-FW-ISO-loopback"


# ---- the brief's tests ----------------------------------------------------------------------


def test_block_scopes_to_the_program_by_default():
    run = FakeRun()
    r = rules_mod.block(run, image=r"C:\x\loader.exe", ip="1.2.3.4", port=443, protocol="tcp")
    cmd = " ".join(run.calls[0])
    assert "-Program" in cmd and r"C:\x\loader.exe" in cmd
    assert "-RemoteAddress 1.2.3.4" in cmd and "-Action Block" in cmd
    assert r["rule_id"].startswith("TDC-FW-")


def test_block_for_everyone_omits_the_program():
    run = FakeRun()
    rules_mod.block(run, ip="1.2.3.4")
    assert "-Program" not in " ".join(run.calls[0])


def test_block_is_verified_before_it_counts():
    run = FakeRun(get_rule_returns="")           # the rule is not there
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert r["verified"] is False


def test_a_disabled_profile_is_reported():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": False})
    assert rules_mod.profiles_off(run) == ["Private", "Public"]


def test_enforcement_refuses_while_a_profile_is_off():
    run = FakeRun(profiles={"Domain": False, "Private": False, "Public": False})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=SETTINGS)
    assert "firewall" in str(e.value).lower()


def test_isolate_remembers_the_previous_outbound_action():
    run, settings = FakeRun(outbound="Allow"), FakeSettings()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.outbound_before == "Allow"
    assert any("DefaultOutboundAction Block" in " ".join(c) for c in run.calls)
    assert any("-Program " + PY in " ".join(c) and "-Action Allow" in " ".join(c) for c in run.calls)
    assert any("127.0.0.0/8" in " ".join(c) for c in run.calls)


def test_leaving_isolated_restores_exactly_what_was_there():
    run, settings = FakeRun(), FakeSettings(outbound_before="Allow", isolated=True)
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert any("DefaultOutboundAction Allow" in " ".join(c) for c in run.calls)
    assert settings.isolated is False and settings.outbound_before is None


def test_isolated_is_never_lifted_on_its_own():
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(FakeRun(outbound="Block"), settings)
    assert state["isolated"] is True and state["announce"] is True


def test_rule_names_are_only_ours():
    run = FakeRun(rule_list=["TDC-FW-abc123", "Core Networking"])
    assert [r["rule_id"] for r in rules_mod.rules(run)] == ["TDC-FW-abc123"]


def test_no_shell_and_no_interpolation_of_malware_text():
    run = FakeRun()
    rules_mod.block(run, image=r'C:\x\a"; Remove-Item C:\ -Recurse #.exe', ip="1.2.3.4")
    assert all(isinstance(c, list) for c in run.calls)
    assert not any(";" in part for part in run.calls[0][1:] if part.startswith("-"))


# ---- the text of a command ------------------------------------------------------------------


def test_malware_text_travels_as_its_own_argument_to_a_file_and_never_to_a_command():
    hostile = r'C:\x\a"; Remove-Item C:\ -Recurse #.exe'
    run = FakeRun()
    rules_mod.block(run, image=hostile, ip="1.2.3.4")
    for call in run.calls:
        assert "-Command" not in call and "-EncodedCommand" not in call
        assert call[0] == rules_mod.POWERSHELL and "-File" in call
        assert call[call.index("-File") + 1].endswith("firewall_rules.ps1")
        for part in call:
            assert part == hostile or "Remove-Item" not in part
    assert hostile in run.calls[0] and run.calls[0][run.calls[0].index(hostile) - 1] == "-Program"


def test_the_ops_the_module_emits_are_the_ops_the_script_accepts():
    script = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    allowed = set(re.findall(r"'(\w+)'", re.search(r"ValidateSet\(([^)]*)\)\]\s*\[string\]\$Op", script).group(1)))
    run, settings = make()
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    rules_mod.unblock(run, run.calls[0][run.calls[0].index("-Name") + 1])
    rules_mod.rules(run)
    rules_mod.enable_firewall(run)
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert set(run.ops()) <= allowed
    assert set(run.ops()) == {"Create", "Get", "Remove", "List", "Enable", "Profiles", "SetDefaultOutbound"}


@pytest.mark.parametrize("image", ["", "-Foo", "C:\\x\\a\nb.exe", "C:\\x\\a\x00.exe", "x" * 5000])
def test_an_image_that_cannot_be_a_path_is_refused(image):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=image, ip="1.2.3.4")
    assert run.calls == []


@pytest.mark.parametrize("kw", [{}, {"image": ""}, {"port": 443, "protocol": "tcp"}, {"ip": "not an ip"},
                                {"ip": "1.2.3.4/8"}, {"ip": "1.2.3.4", "port": 443}, {"ip": "1.2.3.4", "port": 0, "protocol": "tcp"},
                                {"ip": "1.2.3.4", "port": 70000, "protocol": "tcp"},
                                {"ip": "1.2.3.4", "port": 443, "protocol": "icmp"},
                                {"ip": "1.2.3.4", "protocol": "tcp", "image": None, "port": True}])
def test_a_block_that_names_nothing_sound_is_refused_before_anything_runs(kw):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, **kw)
    assert run.calls == []


def test_an_address_is_written_the_way_the_classifier_reads_it():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="::ffff:1.2.3.4")
    assert r["ip"] == "1.2.3.4" and "-RemoteAddress 1.2.3.4" in " ".join(run.calls[0])


# ---- identity -------------------------------------------------------------------------------


def test_the_same_block_has_the_same_id_and_a_different_one_another():
    ids = lambda **kw: rules_mod.block(FakeRun(), **kw)["rule_id"]       # noqa: E731
    a = ids(image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    assert a == ids(image=IMAGE.upper(), ip="1.2.3.4", port=443, protocol="TCP")
    assert re.fullmatch(r"TDC-FW-[0-9a-f]{12}", a)
    others = {ids(image=IMAGE, ip="1.2.3.4", port=443, protocol="udp"),
              ids(image=IMAGE, ip="1.2.3.4", port=444, protocol="tcp"),
              ids(image=IMAGE, ip="1.2.3.4"),
              ids(image=IMAGE, ip="1.2.3.5"),
              ids(ip="1.2.3.4", port=443, protocol="tcp"),
              ids(image=IMAGE)}
    assert a not in others and len(others) == 6


def test_a_program_scoped_and_an_everyone_rule_at_one_address_are_two_rules():
    program = rules_mod.block(FakeRun(), image=IMAGE, ip="1.2.3.4")
    everyone = rules_mod.block(FakeRun(), ip="1.2.3.4")
    assert program["rule_id"] != everyone["rule_id"]


def test_a_blocked_process_without_address_is_program_only():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE)
    cmd = " ".join(run.calls[0])
    assert "-Program" in cmd and "-RemoteAddress" not in cmd and r["verified"] is True


# ---- verifying ------------------------------------------------------------------------------


def test_a_written_rule_that_stands_is_verified_and_says_what_it_is():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    assert r == {"rule_id": r["rule_id"], "name": r["rule_id"], "image": IMAGE, "ip": "1.2.3.4", "port": 443,
                 "protocol": "tcp", "verified": True, "problem": None}
    assert run.ops() == ["Create", "Get", "Profiles"]
    assert rules_mod.verify(run, r["rule_id"]) is True


def test_a_rule_written_but_disabled_is_not_blocking():
    run = FakeRun(disable_new=True)
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert r["verified"] is False and "disabled" in r["problem"]
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_a_rule_that_stands_but_no_longer_bites_because_a_profile_went_off_is_not_verified():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.profiles["Public"] = False
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_verify_fails_closed_when_it_cannot_read_the_profiles():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.fail["Profiles"] = (1, "access denied")
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_verify_of_an_allow_rule_is_false_it_is_not_a_block():
    run = FakeRun()
    run.rules["TDC-FW-x"] = run.view("TDC-FW-x", Action="Allow")
    assert rules_mod.verify(run, "TDC-FW-x") is False


def test_block_refuses_while_a_profile_is_off_and_writes_nothing():
    run = FakeRun(profiles={"Domain": True, "Private": True, "Public": False})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert "firewall" in str(e.value).lower() and "Public" in str(e.value)
    assert run.rules == {}


def test_blocking_the_same_thing_twice_leaves_one_rule_and_does_not_open_a_gap():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    second = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    assert first == second and second["verified"] is True
    assert len(run.rules) == 1
    assert "Remove" not in run.ops()


def test_a_rule_with_our_id_but_other_parameters_is_replaced_and_checked():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.rules[first["rule_id"]]["RemoteAddress"] = ["9.9.9.9"]       # drifted, or tampered with
    again = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert again["verified"] is True
    assert run.rules[first["rule_id"]]["RemoteAddress"] == ["1.2.3.4"]
    assert "Remove" in run.ops()


def test_a_rule_with_our_id_that_is_disabled_is_replaced_not_trusted():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.rules[first["rule_id"]]["Enabled"] = False
    again = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert again["verified"] is True and run.rules[first["rule_id"]]["Enabled"] is True


def test_parameters_that_differ_in_the_spelling_windows_gives_back_still_match():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    view = run.rules[first["rule_id"]]
    view.update(Program=IMAGE.upper(), RemoteAddress=["1.2.3.4/255.255.255.255"], RemotePort=["443"], Protocol="6")
    assert rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")["verified"] is True
    assert "Remove" not in run.ops()


def test_a_failed_write_is_an_error_not_a_quiet_false():
    run = FakeRun(fail={"Create": (1, "The parameter is incorrect.\nmore")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert "incorrect" in str(e.value)


def test_a_runner_that_raises_becomes_a_rule_error():
    def run(args):
        raise FileNotFoundError("powershell")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4")


# ---- unblock and the list -------------------------------------------------------------------


def test_unblock_removes_the_rule_and_makes_sure_it_is_gone():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    rules_mod.unblock(run, r["rule_id"])
    assert run.rules == {} and run.ops()[-2:] == ["Remove", "Get"]


def test_unblock_of_a_rule_that_is_not_there_is_not_an_error():
    rules_mod.unblock(FakeRun(), "TDC-FW-0123456789ab")


def test_unblock_fails_when_the_rule_stays():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.op_Remove = lambda p: (0, "", "")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.unblock(run, r["rule_id"])


@pytest.mark.parametrize("name", ["TDC-FW-*", "TDC-FW-", "Core Networking", "TDC-FW-a b", "TDC-FW-a;b",
                                  "tdc-fw-0123456789ab", "TDC-FW-ISO-fetcher", "TDC-FW-ISO-loopback", "", None, 5])
def test_unblock_touches_nothing_that_is_not_one_of_our_block_rules(name):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.unblock(run, name)
    assert run.calls == []


def test_rules_gives_the_keys_the_classifier_looks_up():
    run = FakeRun()
    a = rules_mod.block(run, image=r"C:\X\Loader.exe", ip="1.2.3.4", port=443, protocol="tcp")
    b = rules_mod.block(run, ip="5.6.7.8")
    c = rules_mod.block(run, image=r"C:\x\other.exe")
    listed = rules_mod.rules(run)
    by_id = {r["rule_id"]: r for r in listed}
    assert by_id[a["rule_id"]]["key"] == firewall.rule_key(r"C:\X\Loader.exe", "1.2.3.4", 443)
    assert by_id[b["rule_id"]]["key"] == firewall.rule_key("", "5.6.7.8", None)
    assert by_id[c["rule_id"]]["key"] == firewall.rule_key(r"C:\x\other.exe", "", None)
    ctx = {r["key"]: r["rule_id"] for r in listed if r["blocking"]}
    assert len(ctx) == 3
    flow = {"image": r"C:\x\loader.exe", "pid": 1, "protocol": "tcp", "src_ip": "10.0.2.15", "dst_ip": "1.2.3.4",
            "dst_port": 443, "count": 1, "first_seen": 0, "last_seen": 0, "times": [0], "dst_hostname": None}
    assert firewall._rule_keys(flow["image"], flow["dst_ip"], flow["dst_port"])[0] in ctx
    assert by_id[a["rule_id"]]["protocol"] == "tcp" and by_id[a["rule_id"]]["port"] == 443


def test_a_listed_rule_blocks_only_when_it_stands_and_the_profiles_are_on():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert [x["blocking"] for x in rules_mod.rules(run)] == [True]
    run.rules[r["rule_id"]]["Enabled"] = False
    assert [x["blocking"] for x in rules_mod.rules(run)] == [False]
    run.rules[r["rule_id"]]["Enabled"] = True
    run.profiles["Private"] = False
    assert [x["blocking"] for x in rules_mod.rules(run)] == [False]


def test_a_rule_we_would_not_have_written_is_listed_but_never_counts_as_a_block():
    run = FakeRun(rule_list=["TDC-FW-abc123"])                 # blocks everything: no program, no address
    run.rules["TDC-FW-def456"] = run.view("TDC-FW-def456", RemoteAddress=["1.2.3.0/24"], Program=IMAGE)
    run.rules["TDC-FW-aaa111"] = run.view("TDC-FW-aaa111", Program=IMAGE, RemoteAddress=["1.2.3.4"],
                                          RemotePort=["80-90"], Protocol="TCP")
    listed = {r["rule_id"]: r for r in rules_mod.rules(run)}
    assert set(listed) == {"TDC-FW-abc123", "TDC-FW-def456", "TDC-FW-aaa111"}
    assert not any(r["blocking"] or r["key"] for r in listed.values())


def test_the_allow_rules_of_isolated_are_listed_as_such_and_never_as_blocks():
    run, settings = make()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    listed = {r["rule_id"]: r for r in rules_mod.rules(run)}
    assert set(listed) == {"TDC-FW-ISO-loopback", "TDC-FW-ISO-fetcher"}
    assert all(r["kind"] == "isolate" and r["action"] == "Allow" and not r["blocking"] for r in listed.values())


def test_a_rule_list_that_cannot_be_read_is_an_error():
    run = FakeRun(fail={"List": (1, "boom")})
    with pytest.raises(rules_mod.RuleError):
        rules_mod.rules(run)
    run = FakeRun()
    run.op_List = lambda p: (0, "not json", "")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.rules(run)


# ---- profiles -------------------------------------------------------------------------------


def test_profiles_off_fails_closed_when_it_cannot_tell():
    with pytest.raises(rules_mod.RuleError):
        rules_mod.profiles_off(FakeRun(fail={"Profiles": (1, "denied")}))
    run = FakeRun()
    run.op_Profiles = lambda p: (0, json.dumps([{"Name": "Domain", "Enabled": True, "DefaultOutboundAction": "Allow"}]), "")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.profiles_off(run)
    run.op_Profiles = lambda p: (0, "", "")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.profiles_off(run)


def test_a_profile_that_is_not_plainly_on_counts_as_off():
    run = FakeRun()
    run.op_Profiles = lambda p: (0, json.dumps([{"Name": n, "Enabled": v, "DefaultOutboundAction": "Allow"}
                                                for n, v in (("Domain", True), ("Private", "NotConfigured"), ("Public", None))]), "")
    assert rules_mod.profiles_off(run) == ["Private", "Public"]


def test_enable_firewall_switches_all_profiles_on_and_checks():
    run = FakeRun(profiles={"Domain": False, "Private": True, "Public": False})
    rules_mod.enable_firewall(run)
    assert run.profiles == ALL_ON and run.ops() == ["Enable", "Profiles"]


def test_enable_firewall_says_so_when_a_profile_stays_off():
    run = FakeRun(profiles={"Domain": False, "Private": True, "Public": False})
    run.op_Enable = lambda p: (0, "", "")
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.enable_firewall(run)
    assert "Domain" in str(e.value)


# ---- isolated -------------------------------------------------------------------------------


def test_isolate_refused_for_a_profile_that_is_off_changes_and_remembers_nothing():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": True})
    settings = FakeSettings()
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert "Private" in str(e.value)
    assert run.ops() == ["Profiles"] and settings.saved == []


def test_isolate_allows_loopback_and_the_fetcher_and_nothing_else():
    run, settings = make()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert set(run.rules) == {"TDC-FW-ISO-loopback", "TDC-FW-ISO-fetcher"}
    loop, fetch = run.rules["TDC-FW-ISO-loopback"], run.rules["TDC-FW-ISO-fetcher"]
    assert loop["Action"] == "Allow" and sorted(loop["RemoteAddress"]) == ["127.0.0.0/8", "::1"] and loop["Program"] == "Any"
    assert fetch["Action"] == "Allow" and fetch["Program"] == PY and fetch["RemoteAddress"] == ["Any"]
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"}


def test_isolate_orders_memory_then_allow_rules_then_block():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    kinds = [t[0] for t in run.timeline]
    first_write = min(i for i, k in enumerate(kinds) if k in ("Create", "SetDefaultOutbound"))
    assert kinds[first_write - 1] == "settings"                       # the way back is saved before anything changes
    assert settings.saved[0] == {"outbound_before": "Allow", "isolated": True, "isolated_since": settings.saved[0]["isolated_since"]}
    assert kinds.index("SetDefaultOutbound") > max(i for i, k in enumerate(kinds) if k == "Create")


def test_isolate_marks_the_time():
    run, settings = make()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.isolated is True and isinstance(settings.isolated_since, float)


def test_isolate_changes_nothing_when_the_way_back_cannot_be_saved():
    run = FakeRun()
    settings = FakeSettings(fail=True)
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert run.writes() == [] and settings.isolated is False


def test_isolating_twice_keeps_the_first_memory():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.outbound_before == "Allow"
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert run.outbound == {"Domain": "Allow", "Private": "Allow", "Public": "Allow"}


def test_a_vm_that_was_already_on_block_comes_back_on_block():
    run, settings = make(outbound="Block")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.outbound_before == "Block"
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"}


def test_profiles_that_differ_come_back_each_as_they_were():
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"}
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert run.outbound == {"Domain": "Block", "Private": "Allow", "Public": "Allow"}


def test_isolate_off_goes_backwards_and_forgets_last():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    run.timeline.clear()
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    kinds = [t[0] for t in run.timeline]
    assert kinds.index("SetDefaultOutbound") < kinds.index("Remove") < kinds.index("settings")
    assert run.rules == {} and settings.outbound_before is None and settings.isolated_since is None


def test_isolate_off_still_works_when_a_profile_is_off():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    run.profiles["Public"] = False
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert settings.isolated is False and run.outbound["Public"] == "Allow"


def test_isolate_off_with_no_memory_assumes_allow_and_says_so():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before=None)
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert out["assumed_allow"] is True and set(run.outbound.values()) == {"Allow"}
    assert settings.isolated is False


def test_isolate_off_when_not_isolated_touches_nothing():
    run, settings = FakeRun(outbound="Allow"), FakeSettings()
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert out["isolated"] is False and out["changed"] is False and out["note"] is None
    assert run.writes() == [] and settings.saved == []


def test_a_memory_nobody_can_read_is_not_obeyed_blindly():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before="Whatever")
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert out["assumed_allow"] is True and set(run.outbound.values()) == {"Allow"}


def test_a_failure_while_switching_rolls_back_to_what_was_there():
    run, settings = make(outbound="Allow", fail_once={"SetDefaultOutbound": (1, "denied")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert "denied" in str(e.value) and "tdc-unisolate" not in str(e.value)
    assert run.rules == {} and settings.isolated is False and settings.outbound_before is None
    assert set(run.outbound.values()) == {"Allow"}


def test_a_failure_writing_the_allow_rules_never_reaches_the_block():
    run, settings = make(outbound="Allow", fail={"Create": (1, "denied")})
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert "SetDefaultOutbound" not in run.ops()
    assert set(run.outbound.values()) == {"Allow"} and settings.isolated is False and settings.outbound_before is None


def test_isolated_is_not_claimed_when_the_block_did_not_take():
    run, settings = make(outbound="Allow")
    run.op_SetDefaultOutbound = lambda p: (0, "", "")             # succeeds and does nothing
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.isolated is False and run.rules == {}


def test_a_rollback_that_fails_keeps_the_marker_and_points_at_the_hatch():
    run, settings = make(outbound="Allow")
    calls = {"n": 0}

    def flaky(p):
        calls["n"] += 1
        return (0, "", "") if calls["n"] == 1 else (1, "", "denied")        # the block does nothing, the undo fails
    run.op_SetDefaultOutbound = flaky
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert "scripts/tdc-unisolate.ps1" in str(e.value)
    assert settings.isolated is True and settings.outbound_before == "Allow"


def test_isolate_needs_a_fetcher():
    for bad in ("", None, "-x"):
        run, settings = make()
        with pytest.raises(rules_mod.RuleError):
            rules_mod.isolate(run, True, fetcher=bad, settings=settings)
        assert run.writes() == [] and settings.saved == []


def test_a_block_written_while_isolated_stands_and_survives_leaving_it():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert r["verified"] is True
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert list(run.rules) == [r["rule_id"]]


# ---- the state at start ---------------------------------------------------------------------


def test_startup_with_nothing_to_say_says_nothing():
    run, settings = FakeRun(), FakeSettings()
    state = rules_mod.startup_state(run, settings)
    assert state == {"isolated": False, "profiles_off": [], "announce": False, "note": None}


def test_a_marker_over_an_open_egress_is_cleared_because_the_hatch_was_used():
    run, settings = FakeRun(outbound="Allow"), FakeSettings(isolated=True, outbound_before="Allow", isolated_since=1.0)
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and settings.isolated is False and settings.outbound_before is None
    assert state["announce"] is True and "stale" in state["note"]
    assert run.writes() == []


def test_isolated_with_a_profile_off_is_not_called_isolated_but_is_announced_and_kept():
    run = FakeRun(outbound="Block", profiles={"Domain": True, "Private": True, "Public": False})
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and state["announce"] is True and state["profiles_off"] == ["Public"]
    assert settings.isolated is True and settings.outbound_before == "Allow"


def test_isolated_on_some_profiles_only_is_announced_and_kept():
    run = FakeRun(outbound={"Domain": "Allow", "Private": "Block", "Public": "Block"})
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and state["announce"] is True and settings.isolated is True


def test_startup_that_cannot_read_the_firewall_keeps_the_marker_and_announces():
    run = FakeRun(fail={"Profiles": (1, "denied")})
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["announce"] is True and state["note"]
    assert settings.isolated is True


def test_startup_reports_the_profiles_that_are_off():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": False})
    assert rules_mod.startup_state(run, FakeSettings())["profiles_off"] == ["Private", "Public"]


# ---- kill -----------------------------------------------------------------------------------


def test_kill_is_taskkill_with_the_pid_and_nothing_else():
    run = FakeRun()
    rules_mod.kill(run, 4812)
    assert run.calls == [[rules_mod.TASKKILL, "/PID", "4812", "/F"]]


@pytest.mark.parametrize("pid", [0, 4, -1, os.getpid(), "4812; calc", None, True, 1.5])
def test_kill_refuses_a_pid_it_must_not_or_cannot_kill(pid):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.kill(run, pid)
    assert run.calls == []


def test_kill_that_fails_says_why():
    run = FakeRun(fail={"taskkill": (128, "", "ERROR: The process \"5\" not found.")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.kill(run, 5000)
    assert "not found" in str(e.value)


# ---- the real runner ------------------------------------------------------------------------


def test_run_powershell_returns_code_and_both_streams_without_a_shell():
    code = "import sys; print('a b;c|d'); sys.stderr.write('e'); sys.exit(3)"
    rc, out, err = rules_mod.run_powershell([sys.executable, "-c", code])
    assert (rc, out.strip(), err) == (3, "a b;c|d", "e")


def test_run_powershell_does_not_raise_for_a_program_that_is_not_there():
    rc, out, err = rules_mod.run_powershell(["definitely-not-a-program-tdc"])
    assert rc != 0 and out == "" and err


# ---- the scripts ----------------------------------------------------------------------------


def test_the_hatch_restores_outbound_and_removes_every_rule_of_ours():
    text = open(os.path.join(ROOT, "scripts", "tdc-unisolate.ps1"), encoding="utf-8").read()
    assert "-DefaultOutboundAction Allow" in text and "TDC-FW-*" in text
    assert "Remove-NetFirewallRule" in text and "Invoke-Expression" not in text


def test_the_helper_script_runs_no_text_it_was_given():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    for bad in ("Invoke-Expression", "iex ", "Start-Process", "cmd /c", "[scriptblock]::Create"):
        assert bad not in text
    assert "TDC-FW-" in text and "WildcardPattern" in text


# ---- the marker is the only authority for "TDC is isolating" ---------------------------------


def test_a_shut_egress_without_a_marker_is_not_isolated_but_is_announced_and_left_alone():
    run, settings = FakeRun(outbound="Block"), FakeSettings()
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and state["announce"] is True and state["profiles_off"] == []
    assert "did not set it" in state["note"] and "tdc-unisolate" in state["note"]
    assert run.writes() == [] and settings.saved == []


def test_leaving_without_a_marker_leaves_a_shut_egress_shut_and_says_why():
    run, settings = FakeRun(outbound="Block"), FakeSettings()
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert out["changed"] is False and "not isolating" in out["note"] and "tdc-unisolate" in out["note"]
    assert run.writes() == [] and set(run.outbound.values()) == {"Block"}


def test_isolating_from_a_baseline_that_is_already_block_and_leaving_it_back_to_block():
    run, settings = make(outbound="Block")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.isolated is True and settings.outbound_before == "Block"
    assert FETCHER in run.rules and LOOPBACK in run.rules
    assert rules_mod.startup_state(run, settings)["isolated"] is True
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert out["isolated"] is False and set(run.outbound.values()) == {"Block"} and run.rules == {}
    assert "baseline" in out["note"] and "not a TDC lockout" in out["note"] and "Domain, Private, Public" in out["note"]
    assert settings.isolated is False and settings.outbound_before is None


def test_leaving_to_a_baseline_that_is_open_has_nothing_to_explain():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert rules_mod.isolate(run, False, fetcher=PY, settings=settings)["note"] is None


def test_a_mixed_baseline_names_the_profiles_that_stay_shut():
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    out = rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert "Block on Domain:" in out["note"]


def test_a_marker_without_a_baseline_says_it_assumed_allow():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before=None)
    assert "assumed" in rules_mod.isolate(run, False, fetcher=PY, settings=settings)["note"]


# ---- several rules, one key ------------------------------------------------------------------


def test_two_rules_that_share_a_key_come_back_as_two_entries_with_their_own_protocol():
    run = FakeRun()
    tcp = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    udp = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="udp")
    assert tcp["rule_id"] != udp["rule_id"]
    listed = {r["rule_id"]: r for r in rules_mod.rules(run)}
    assert set(listed) == {tcp["rule_id"], udp["rule_id"]}
    assert listed[tcp["rule_id"]]["key"] == listed[udp["rule_id"]]["key"]
    assert (listed[tcp["rule_id"]]["protocol"], listed[udp["rule_id"]]["protocol"]) == ("tcp", "udp")
    assert all(r["blocking"] for r in listed.values())
    by_key = {}
    for r in listed.values():
        by_key.setdefault(r["key"], []).append(r["rule_id"])
    for rule_id in by_key[listed[tcp["rule_id"]]["key"]]:
        rules_mod.unblock(run, rule_id)
    assert rules_mod.rules(run) == []


# ---- a replacement never leaves a gap --------------------------------------------------------


def tamper_with_the_fetcher_rule(run):
    run.rules[FETCHER]["RemoteAddress"] = ["9.9.9.9"]


def test_replacing_the_fetchers_allow_rule_while_isolated_never_leaves_none():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    tamper_with_the_fetcher_rule(run)
    run.standing.clear()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert run.standing and all(any(a == "Allow" and prog == PY for _, a, prog in moment) for moment in run.standing)
    assert run.rules[FETCHER]["RemoteAddress"] == ["Any"] and FETCHER + "-new" not in run.rules
    assert settings.isolated is True and set(run.outbound.values()) == {"Block"}


def test_a_replacement_that_fails_halfway_keeps_the_stand_in_and_names_the_hatch():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    tamper_with_the_fetcher_rule(run)
    real = run.op_Create
    seen = {"n": 0}

    def create(p):
        seen["n"] += 1
        return (1, "", "denied") if seen["n"] == 4 else real(p)       # loopback exists, fetcher exists, the stand-in is written, the new one fails
    run.op_Create = create
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert "scripts/tdc-unisolate.ps1" in str(e.value) and "denied" in str(e.value)
    assert FETCHER + "-new" in run.rules and run.rules[FETCHER + "-new"]["Program"] == PY
    assert settings.isolated is True and set(run.outbound.values()) == {"Block"}      # not rolled back to open


def test_the_stand_in_goes_with_isolated_and_can_be_unblocked_by_hand():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    run.rules[FETCHER + "-new"] = run.view(FETCHER + "-new", Action="Allow", Program=PY)
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert run.rules == {}
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.rules[r["rule_id"] + "-new"] = run.view(r["rule_id"] + "-new")
    rules_mod.unblock(run, r["rule_id"] + "-new")
    assert r["rule_id"] + "-new" not in run.rules


def test_replacing_a_block_does_not_open_a_gap_either():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    run.rules[first["rule_id"]]["Enabled"] = False
    run.standing.clear()
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert all(any(a == "Block" and prog == IMAGE for _, a, prog in moment) for moment in run.standing)


# ---- the lockout targets ---------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.8.9.1", "::1", "0.0.0.0", "::", "224.0.0.251", "ff02::fb", "::ffff:127.0.0.1"])
@pytest.mark.parametrize("image", [None, IMAGE])
def test_an_address_that_would_cut_tdc_off_from_itself_is_refused(ip, image):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=image, ip=ip)
    assert run.calls == []


def test_a_block_on_the_fetcher_itself_is_refused_when_the_caller_names_it():
    run = FakeRun()
    for image in (PY, PY.upper(), PY.replace("\\", "/"), "  " + PY):
        with pytest.raises(rules_mod.RuleError) as e:
            rules_mod.block(run, image=image, ip="1.2.3.4", fetcher=PY)
        assert "fetcher" in str(e.value)
        with pytest.raises(rules_mod.RuleError):
            rules_mod.block(run, image=image, fetcher=PY)
    assert run.calls == []
    assert rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)["verified"] is True
    assert rules_mod.block(run, ip="1.2.3.4", fetcher=PY)["verified"] is True


# ---- names, paths, digits --------------------------------------------------------------------


@pytest.mark.parametrize("name", ["TDC-FW-0123456789ab\n", "TDC-FW-0123456789ab-new\n"])
def test_a_trailing_newline_does_not_make_a_name(name):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.unblock(run, name)
    assert rules_mod.verify(run, name) is False
    assert run.calls == []


def test_the_script_refuses_a_trailing_newline_too():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    assert r"{1,40}\z'" in text


def test_the_system_tools_are_called_by_absolute_path():
    assert ntpath.isabs(rules_mod.POWERSHELL) and rules_mod.POWERSHELL.lower().endswith(r"\system32\windowspowershell\v1.0\powershell.exe")
    assert ntpath.isabs(rules_mod.TASKKILL) and rules_mod.TASKKILL.lower().endswith(r"\system32\taskkill.exe")
    run = FakeRun()
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    rules_mod.kill(run, 4812)
    assert all(ntpath.isabs(c[0]) for c in run.calls)


@pytest.mark.parametrize("port", ["\u0664\u0664\u0663", "\uff14\uff14\uff13", "\u00b2"])
def test_a_port_in_other_digits_is_refused(port):
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(FakeRun(), ip="1.2.3.4", port=port, protocol="tcp")


def test_a_port_in_ascii_digits_as_text_still_works():
    assert rules_mod.block(FakeRun(), ip="1.2.3.4", port="443", protocol="tcp")["port"] == 443


# ---- the two halves agree on the names -------------------------------------------------------


def test_every_parameter_the_module_emits_is_declared_by_the_script():
    script = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    block_text = re.search(r"^param\((.*?)^\)", script, re.S | re.M).group(1)
    declared = set(re.findall(r"\$(\w+)\s*[,\n]", block_text + "\n"))
    assert {"Op", "Name", "Program", "RemoteAddress", "RemotePort", "Protocol", "Action", "Profiles",
            "DefaultOutboundAction"} <= declared
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp")
    rules_mod.block(run, image=IMAGE)
    rules_mod.rules(run)
    rules_mod.enable_firewall(run)
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    emitted = set()
    for call in run.calls:
        if ntpath.basename(call[0]).lower() == "powershell.exe":
            rest = call[call.index("-File") + 2:]
            emitted |= {rest[i][1:] for i in range(0, len(rest), 2)}
            assert all(rest[i].startswith("-") for i in range(0, len(rest), 2))
    assert {"Profiles", "RemotePort", "Protocol", "Program", "RemoteAddress", "DefaultOutboundAction"} <= emitted
    assert emitted <= declared, emitted - declared
