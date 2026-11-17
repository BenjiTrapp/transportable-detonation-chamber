"""Enforcement of the FIREWALL tab (webui/firewall_rules.py).

Nothing here touches a firewall: ``FakeRun`` stands in for ``run_powershell``. It speaks the contract of
webui/firewall_rules.ps1 (the ``-Op`` verbs, exit code 3 for "a profile is off", 4 for "the rule is already
there"), so these tests prove the Python side, the order of what it does and what it refuses to claim. What the
script really does to Windows only a VM can show.
"""

import base64
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
                 fail_once=None, disable_new=False, timeline=None, foreign=None, stubborn=(), repair_fails=False):
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
        self.repair_fails = repair_fails   # Set-NetFirewallRule on the cut rule errors and changes nothing
        self.standing = []          # (name, action, program) of every rule, after each call
        # Windows' own outbound Allow rules: name -> {DisplayName, Group, Source, Enabled}; ``stubborn`` will not switch
        self.foreign = {n: dict(r) for n, r in (foreign or {}).items()}
        self.stubborn = set(stubborn)
        self.stuck_rules = set()     # TDC-FW-ISO-* rules RemoveIsolate cannot remove
        self.forced = {}             # profile -> DefaultOutboundAction a group policy puts in force

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
        """``outbound`` is what is configured (the PersistentStore SetDefaultOutbound writes); in force (the ActiveStore)
        NotConfigured resolves to Allow, or to what ``forced`` (a group policy) says."""
        rows = []
        for n, on in self.profiles.items():
            configured = self.outbound.get(n, "Allow")
            active = self.forced.get(n) or ("Allow" if configured == "NotConfigured" else configured)
            rows.append({"Name": n, "Enabled": on, "DefaultOutboundAction": active, "Configured": configured})
        return rows

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

    CATCH_ALL = {"Enabled": True, "Action": "Block", "Direction": "Outbound", "Profile": "Any", "Program": "Any",
                 "RemoteAddress": ["Any"], "RemotePort": ["Any"], "Protocol": "Any"}

    def op_Cut(self, p):
        """The whole verb in one call: profiles checked, the rule written if it is not there, brought to the catch-all
        shape *in place* if it is there in another (Set-NetFirewallRule: the rule is never absent), its view given as ``Get`` does."""
        assert set(p) == {"Op"}, p          # the verb takes no parameter: nothing of it can come from outside
        if self.off():
            return 3, "", ", ".join(self.off())
        err = ""
        if rules_mod.CUT_RULE not in self.rules:
            self.rules[rules_mod.CUT_RULE] = self.view(rules_mod.CUT_RULE, Action="Block", Enabled=not self.disable_new)
        elif any(self.rules[rules_mod.CUT_RULE].get(k) != v for k, v in self.CATCH_ALL.items()):
            if self.repair_fails:
                err = "Set-NetFirewallRule: access is denied"
            else:
                self.rules[rules_mod.CUT_RULE].update(self.CATCH_ALL)
        rc, out, _ = self.op_Get({"Name": rules_mod.CUT_RULE})
        return rc, out, err

    def op_Remove(self, p):
        self.rules.pop(p["Name"], None)
        return 0, "", ""

    def op_AllowOut(self, p):
        rows = [{"Name": n, "DisplayName": r.get("DisplayName", n), "Group": r.get("Group", ""), "Source": r["Source"]}
                for n, r in self.foreign.items() if r["Enabled"]]
        return 0, json.dumps({"profiles": self.profile_rows(), "rules": rows}), ""

    def _toggle(self, p, on):
        done, failed, missing = [], [], []
        for n in json.loads(base64.b64decode(p["Names"]).decode("utf-8")):
            r = self.foreign.get(n)
            if r is None or r["Source"] != "Local":
                missing.append(n)
            elif n in self.stubborn:
                failed.append({"Name": n, "Error": "access is denied"})
            else:
                r["Enabled"] = on
                done.append(n)
        return 0, json.dumps({"done": done, "failed": failed, "missing": missing}), ""

    def op_DisableAllowOut(self, p):
        return self._toggle(p, False)

    def op_EnableAllowOut(self, p):
        return self._toggle(p, True)

    def enabled_foreign(self):
        return sorted(n for n, r in self.foreign.items() if r["Enabled"])

    def op_SetDefaultOutbound(self, p):
        names = p["Profiles"].split(",") if "Profiles" in p else list(self.profiles)
        for n in names:
            self.outbound[n] = p["DefaultOutboundAction"]
        return 0, json.dumps(self.profile_rows()), ""

    def op_RemoveIsolate(self, p):
        names = [n for n in self.rules if n.startswith("TDC-FW-ISO-")]
        for n in names:
            if n not in self.stuck_rules:
                self.rules.pop(n)
        still = [n for n in names if n in self.rules]
        return 0, json.dumps({"removed": [n for n in names if n not in still], "still": still}), ""

    # -- what a test looks at --

    def ops(self):
        return [self.params(c)["Op"] for c in self.calls if c[0] != "taskkill"]

    def writes(self):
        return [o for o in self.ops() if o in ("Create", "Remove", "SetDefaultOutbound", "Enable", "DisableAllowOut",
                                               "EnableAllowOut", "RemoveIsolate")]


class FakeSettings:
    def __init__(self, outbound_before=None, isolated=False, isolated_since=None, timeline=None, fail=False,
                 allow_disabled=(), stage="open"):
        self.outbound_before = outbound_before
        self.stage = stage
        self.allow_disabled = list(allow_disabled)
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
# A stock Windows: Core Networking's DNS and DHCP rules are local and enabled, a group policy adds one of its own
DNS_RULE = "CoreNet-DNS-Out-UDP"
STOCK = {
    DNS_RULE: {"DisplayName": "Core Networking - DNS (UDP-Out)", "Group": "Core Networking", "Source": "Local", "Enabled": True},
    "CoreNet-DHCP-Out": {"DisplayName": "Core Networking - DHCP (DHCP-Out)", "Group": "Core Networking", "Source": "Local", "Enabled": True},
    "CoreNet-Teredo-Out": {"DisplayName": "Core Networking - Teredo (UDP-Out)", "Group": "Core Networking", "Source": "Local", "Enabled": False},
}
GPO_RULE = {"{gpo-1}": {"DisplayName": "Lab proxy out", "Group": "", "Source": "GroupPolicy", "Enabled": True}}
POLICY_STOCK = {**STOCK, **GPO_RULE}      # a rule no switch from here can turn off: the convergence ends in cut_policy


def _after_calls(run, n):
    """A ``cancelled`` that turns True once ``run`` has seen ``n`` more calls than it had when this was made."""
    start = len(run.calls)
    return lambda: len(run.calls) - start >= n


def thorough(run, settings):
    """What ISOLATED on was before the panic cut: the cut, then the convergence behind it. ``verified`` and the lists
    are those of the convergence; the rest is the answer of the press."""
    pressed = rules_mod.isolate(run, True, settings=settings)
    tidied = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    notes = " ".join(n for n in (pressed["note"], tidied["note"]) if n)
    return {**pressed, **tidied, "note": notes or None}


# ---- the brief's tests ----------------------------------------------------------------------


def test_block_scopes_to_the_program_by_default():
    run = FakeRun()
    r = rules_mod.block(run, image=r"C:\x\loader.exe", ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    cmd = " ".join(run.calls[0])
    assert "-Program" in cmd and r"C:\x\loader.exe" in cmd
    assert "-RemoteAddress 1.2.3.4" in cmd and "-Action Block" in cmd
    assert r["rule_id"].startswith("TDC-FW-")


def test_block_for_everyone_omits_the_program():
    run = FakeRun()
    rules_mod.block(run, ip="1.2.3.4", fetcher=PY)
    assert "-Program" not in " ".join(run.calls[0])


def test_block_is_verified_before_it_counts():
    run = FakeRun(get_rule_returns="")           # the rule is not there
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert r["verified"] is False


def test_a_disabled_profile_is_reported():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": False})
    assert rules_mod.profiles_off(run) == ["Private", "Public"]


def test_enforcement_refuses_while_a_profile_is_off():
    run = FakeRun(profiles={"Domain": False, "Private": False, "Public": False})
    with pytest.raises(rules_mod.RuleError) as e:
        thorough(run, SETTINGS)
    assert "firewall" in str(e.value).lower()


def test_isolate_remembers_the_previous_outbound_action():
    run, settings = FakeRun(outbound="Allow"), FakeSettings()
    thorough(run, settings)
    assert settings.outbound_before == "Allow"
    assert any("DefaultOutboundAction Block" in " ".join(c) for c in run.calls)
    assert not any("-Program" in c for c in run.calls)     # the fetcher's way out is per fetch, see allow_fetch
    assert "Create" not in run.ops()                       # loopback needs no rule: Windows does not filter it


def test_leaving_isolated_restores_exactly_what_was_there():
    run, settings = FakeRun(), FakeSettings(outbound_before="Allow", isolated=True)
    rules_mod.isolate(run, False, settings=settings)
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
    rules_mod.block(run, image=r'C:\x\a"; Remove-Item C:\ -Recurse #.exe', ip="1.2.3.4", fetcher=PY)
    assert all(isinstance(c, list) for c in run.calls)
    assert not any(";" in part for part in run.calls[0][1:] if part.startswith("-"))


# ---- the text of a command ------------------------------------------------------------------


def test_malware_text_travels_as_its_own_argument_to_a_file_and_never_to_a_command():
    hostile = r'C:\x\a"; Remove-Item C:\ -Recurse #.exe'
    run = FakeRun()
    rules_mod.block(run, image=hostile, ip="1.2.3.4", fetcher=PY)
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
    run, settings = make(foreign=STOCK)
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    rules_mod.unblock(run, run.calls[0][run.calls[0].index("-Name") + 1])
    rules_mod.rules(run)
    rules_mod.enable_firewall(run)
    thorough(run, settings)
    rules_mod.isolate(run, False, settings=settings)
    rules_mod.cut(run)
    rules_mod.uncut(run)
    assert set(run.ops()) <= allowed
    assert set(run.ops()) == {"Create", "Get", "Remove", "List", "Enable", "Profiles", "SetDefaultOutbound", "AllowOut",
                              "DisableAllowOut", "EnableAllowOut", "RemoveIsolate", "Cut"}


@pytest.mark.parametrize("image", ["", "-Foo", "C:\\x\\a\nb.exe", "C:\\x\\a\x00.exe", "x" * 5000])
def test_an_image_that_cannot_be_a_path_is_refused(image):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=image, ip="1.2.3.4", fetcher=PY)
    assert run.calls == []


@pytest.mark.parametrize("kw", [{}, {"image": ""}, {"port": 443, "protocol": "tcp"}, {"ip": "not an ip"},
                                {"ip": "1.2.3.4/8"}, {"ip": "1.2.3.4", "port": 443}, {"ip": "1.2.3.4", "port": 0, "protocol": "tcp"},
                                {"ip": "1.2.3.4", "port": 70000, "protocol": "tcp"},
                                {"ip": "1.2.3.4", "port": 443, "protocol": "icmp"},
                                {"ip": "1.2.3.4", "protocol": "tcp", "image": None, "port": True}])
def test_a_block_that_names_nothing_sound_is_refused_before_anything_runs(kw):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, **kw, fetcher=PY)
    assert run.calls == []


def test_an_address_is_written_the_way_the_classifier_reads_it():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="::ffff:1.2.3.4", fetcher=PY)
    assert r["ip"] == "1.2.3.4" and "-RemoteAddress 1.2.3.4" in " ".join(run.calls[0])


# ---- identity -------------------------------------------------------------------------------


def test_the_same_block_has_the_same_id_and_a_different_one_another():
    ids = lambda **kw: rules_mod.block(FakeRun(), **kw, fetcher=PY)["rule_id"]       # noqa: E731
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
    program = rules_mod.block(FakeRun(), image=IMAGE, ip="1.2.3.4", fetcher=PY)
    everyone = rules_mod.block(FakeRun(), ip="1.2.3.4", fetcher=PY)
    assert program["rule_id"] != everyone["rule_id"]


def test_a_blocked_process_without_address_is_program_only():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, fetcher=PY)
    cmd = " ".join(run.calls[0])
    assert "-Program" in cmd and "-RemoteAddress" not in cmd and r["verified"] is True


# ---- verifying ------------------------------------------------------------------------------


def test_a_written_rule_that_stands_is_verified_and_says_what_it_is():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    assert r == {"rule_id": r["rule_id"], "name": r["rule_id"], "image": IMAGE, "ip": "1.2.3.4", "port": 443,
                 "protocol": "tcp", "verified": True, "problem": None}
    assert run.ops() == ["Create", "Get", "Profiles"]
    assert rules_mod.verify(run, r["rule_id"]) is True


def test_a_rule_written_but_disabled_is_not_blocking():
    run = FakeRun(disable_new=True)
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert r["verified"] is False and "disabled" in r["problem"]
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_a_rule_that_stands_but_no_longer_bites_because_a_profile_went_off_is_not_verified():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.profiles["Public"] = False
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_verify_fails_closed_when_it_cannot_read_the_profiles():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.fail["Profiles"] = (1, "access denied")
    assert rules_mod.verify(run, r["rule_id"]) is False


def test_verify_of_an_allow_rule_is_false_it_is_not_a_block():
    run = FakeRun()
    run.rules["TDC-FW-x"] = run.view("TDC-FW-x", Action="Allow")
    assert rules_mod.verify(run, "TDC-FW-x") is False


def test_block_refuses_while_a_profile_is_off_and_writes_nothing():
    run = FakeRun(profiles={"Domain": True, "Private": True, "Public": False})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert "firewall" in str(e.value).lower() and "Public" in str(e.value)
    assert run.rules == {}


def test_blocking_the_same_thing_twice_leaves_one_rule_and_does_not_open_a_gap():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    second = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    assert first == second and second["verified"] is True
    assert len(run.rules) == 1
    assert "Remove" not in run.ops()


def test_a_rule_with_our_id_but_other_parameters_is_replaced_and_checked():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.rules[first["rule_id"]]["RemoteAddress"] = ["9.9.9.9"]       # drifted, or tampered with
    again = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert again["verified"] is True
    assert run.rules[first["rule_id"]]["RemoteAddress"] == ["1.2.3.4"]
    assert "Remove" in run.ops()


def test_a_rule_with_our_id_that_is_disabled_is_replaced_not_trusted():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.rules[first["rule_id"]]["Enabled"] = False
    again = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert again["verified"] is True and run.rules[first["rule_id"]]["Enabled"] is True


def test_parameters_that_differ_in_the_spelling_windows_gives_back_still_match():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    view = run.rules[first["rule_id"]]
    view.update(Program=IMAGE.upper(), RemoteAddress=["1.2.3.4/255.255.255.255"], RemotePort=["443"], Protocol="6")
    assert rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)["verified"] is True
    assert "Remove" not in run.ops()


def test_a_failed_write_is_an_error_not_a_quiet_false():
    run = FakeRun(fail={"Create": (1, "The parameter is incorrect.\nmore")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert "incorrect" in str(e.value)


def test_a_runner_that_raises_becomes_a_rule_error():
    def run(args):
        raise FileNotFoundError("powershell")
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)


# ---- unblock and the list -------------------------------------------------------------------


def test_unblock_removes_the_rule_and_makes_sure_it_is_gone():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    rules_mod.unblock(run, r["rule_id"])
    assert run.rules == {} and run.ops()[-2:] == ["Remove", "Get"]


def test_unblock_of_a_rule_that_is_not_there_is_not_an_error():
    rules_mod.unblock(FakeRun(), "TDC-FW-0123456789ab")


def test_unblock_fails_when_the_rule_stays():
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
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
    a = rules_mod.block(run, image=r"C:\X\Loader.exe", ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    b = rules_mod.block(run, ip="5.6.7.8", fetcher=PY)
    c = rules_mod.block(run, image=r"C:\x\other.exe", fetcher=PY)
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
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
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
    thorough(run, settings)
    fetch = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    listed = {r["rule_id"]: r for r in rules_mod.rules(run)}
    assert set(listed) == {fetch}
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
    with pytest.raises(rules_mod.ProfileOffError) as e:
        thorough(run, settings)
    assert "Private" in str(e.value)
    assert run.ops() == ["Profiles"] and settings.saved == []


def test_isolate_writes_no_allow_rule_of_its_own():
    """Windows Firewall does not filter loopback, and refuses ::1 as a RemoteAddress: the loopback rule of older
    versions was a no-op that made every isolation fail. The fetcher's way out is per fetch (allow_fetch)."""
    run, settings = make()
    out = thorough(run, settings)
    assert run.rules == {} and "Create" not in run.ops() and not any("::1" in c for c in run.calls)
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"} and out["verified"] is True


def test_isolate_orders_memory_then_allow_rules_then_block():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    kinds = [t[0] for t in run.timeline]
    first_write = min(i for i, k in enumerate(kinds) if k in ("Create", "Cut", "DisableAllowOut", "SetDefaultOutbound"))
    assert kinds[first_write - 1] == "settings"                       # the way back is saved before anything changes
    assert settings.saved[0] == {"outbound_before": "Allow", "isolated": True, "isolated_since": settings.saved[0]["isolated_since"]}
    assert "Create" not in kinds


def test_isolate_marks_the_time():
    run, settings = make()
    thorough(run, settings)
    assert settings.isolated is True and isinstance(settings.isolated_since, float)


def test_isolate_changes_nothing_when_the_way_back_cannot_be_saved():
    run = FakeRun()
    settings = FakeSettings(fail=True)
    with pytest.raises(rules_mod.RuleError):
        thorough(run, settings)
    assert run.writes() == [] and settings.isolated is False


def test_isolating_twice_keeps_the_first_memory():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    thorough(run, settings)
    assert settings.outbound_before == "Allow"
    rules_mod.isolate(run, False, settings=settings)
    assert run.outbound == {"Domain": "Allow", "Private": "Allow", "Public": "Allow"}


def test_a_vm_that_was_already_on_block_comes_back_on_block():
    run, settings = make(outbound="Block")
    thorough(run, settings)
    assert settings.outbound_before == "Block"
    rules_mod.isolate(run, False, settings=settings)
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"}


def test_profiles_that_differ_come_back_each_as_they_were():
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    thorough(run, settings)
    assert run.outbound == {"Domain": "Block", "Private": "Block", "Public": "Block"}
    rules_mod.isolate(run, False, settings=settings)
    assert run.outbound == {"Domain": "Block", "Private": "Allow", "Public": "Allow"}


def test_isolate_off_goes_backwards_and_forgets_last():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    run.timeline.clear()
    rules_mod.isolate(run, False, settings=settings)
    kinds = [t[0] for t in run.timeline]
    assert kinds.index("SetDefaultOutbound") < kinds.index("RemoveIsolate") < kinds.index("settings")
    assert run.rules == {} and settings.outbound_before is None and settings.isolated_since is None


def test_isolate_off_still_works_when_a_profile_is_off():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    run.profiles["Public"] = False
    rules_mod.isolate(run, False, settings=settings)
    assert settings.isolated is False and run.outbound["Public"] == "Allow"


def test_isolate_off_with_no_memory_assumes_allow_and_says_so():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before=None)
    out = rules_mod.isolate(run, False, settings=settings)
    assert out["assumed_allow"] is True and set(run.outbound.values()) == {"Allow"}
    assert settings.isolated is False


def test_isolate_off_when_not_isolated_touches_nothing():
    run, settings = FakeRun(outbound="Allow"), FakeSettings()
    out = rules_mod.isolate(run, False, settings=settings)
    assert out["isolated"] is False and out["changed"] is False and out["note"] is None
    assert run.writes() == [] and settings.saved == []


def test_a_memory_nobody_can_read_is_not_obeyed_blindly():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before="Whatever")
    out = rules_mod.isolate(run, False, settings=settings)
    assert out["assumed_allow"] is True and set(run.outbound.values()) == {"Allow"}


def test_a_default_action_that_will_not_change_leaves_the_cut_standing_and_nothing_rolled_back():
    run, settings = make(outbound="Allow", foreign=STOCK, fail_once={"SetDefaultOutbound": (1, "denied")})
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and done["verified"] is False and "denied" in done["note"]
    assert rules_mod.CUT_RULE in run.rules and settings.isolated is True and settings.stage == "cut"
    assert sorted(settings.allow_disabled) == ["CoreNet-DHCP-Out", DNS_RULE]      # the way back stays noted
    assert run.enabled_foreign() == [] and "EnableAllowOut" not in run.ops()      # what was switched off stays off
    assert set(run.outbound.values()) == {"Allow"}


def test_a_failure_switching_windows_rules_off_never_reaches_the_block():
    run, settings = make(outbound="Allow", foreign=STOCK, fail={"DisableAllowOut": (1, "denied")})
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and "denied" in done["note"]
    assert "SetDefaultOutbound" not in run.ops() and run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]
    assert set(run.outbound.values()) == {"Allow"} and settings.isolated is True and settings.outbound_before == "Allow"
    assert rules_mod.CUT_RULE in run.rules


def test_isolated_is_not_claimed_when_the_block_did_not_take():
    run, settings = make(outbound="Allow")
    rules_mod.isolate(run, True, settings=settings)
    run.op_SetDefaultOutbound = lambda p: (0, "", "")             # succeeds and does nothing
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and done["verified"] is False and "did not change" in done["note"]
    assert rules_mod.CUT_RULE in run.rules and settings.isolated is True and settings.stage == "cut"


def test_a_rollback_that_fails_keeps_the_marker_and_points_at_the_hatch():
    run, settings = make(outbound="Allow", fail={"Cut": (1, "denied"), "RemoveIsolate": (1, "denied")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, settings=settings)                  # the cut fails, and so does the undo
    assert "scripts/tdc-unisolate.ps1" in str(e.value)
    assert settings.isolated is True and settings.outbound_before == "Allow"


def test_the_way_out_of_isolated_needs_a_usable_fetcher_and_address():
    for bad in ("", None, "-x"):
        run = FakeRun()
        with pytest.raises(rules_mod.RuleError):
            rules_mod.allow_fetch(run, fetcher=bad, ip="1.2.3.4")
        assert run.writes() == []
    for bad in ("", None, "not-an-ip", "1.2.3.4/24"):
        run = FakeRun()
        with pytest.raises(rules_mod.RuleError):
            rules_mod.allow_fetch(run, fetcher=PY, ip=bad)
        assert run.writes() == []


def test_a_block_written_while_isolated_stands_and_survives_leaving_it():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert r["verified"] is True
    rules_mod.isolate(run, False, settings=settings)
    assert list(run.rules) == [r["rule_id"]]


# ---- the way out of ISOLATED, one fetch at a time --------------------------------------------


def test_a_per_fetch_rule_names_one_program_one_address_and_one_port():
    run = FakeRun()
    done = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)
    assert done["verified"] is True and done["problem"] is None
    assert done["name"].startswith(rules_mod.FETCH_PREFIX)
    rule = run.rules[done["name"]]
    assert rule["Action"] == "Allow" and rule["Program"] == PY and rule["RemoteAddress"] == ["1.2.3.4"]
    assert rule["RemotePort"] == ["8080"] and rule["Protocol"] == "TCP"


def test_a_per_fetch_rule_without_a_port_covers_the_address():
    run = FakeRun()
    done = rules_mod.allow_fetch(run, fetcher=PY, ip="2001:db8::1")
    rule = run.rules[done["name"]]
    assert rule["RemoteAddress"] == ["2001:db8::1"] and rule["RemotePort"] == ["Any"] and rule["Protocol"] == "Any"


def test_one_endpoint_is_one_rule_and_two_endpoints_are_two():
    same = (rules_mod.fetch_rule_name("1.2.3.4", 8080, PY), rules_mod.fetch_rule_name("1.2.3.4", 8080, PY))
    assert same[0] == same[1]
    assert len({rules_mod.fetch_rule_name("1.2.3.4", 8080, PY), rules_mod.fetch_rule_name("1.2.3.4", 443, PY),
                rules_mod.fetch_rule_name("5.6.7.8", 8080, PY), rules_mod.fetch_rule_name("1.2.3.4", None, PY),
                rules_mod.fetch_rule_name("1.2.3.4", 8080, r"C:\Python312\python.exe"),
                rules_mod.fetch_rule_name("1.2.3.4", 8080)}) == 6


def test_the_two_binaries_a_venv_fetch_can_run_as_get_a_rule_each():
    run = FakeRun()
    base = r"C:\Python312\python.exe"
    first = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)
    second = rules_mod.allow_fetch(run, fetcher=base, ip="1.2.3.4", port=8080)
    assert first["name"] != second["name"] and first["verified"] and second["verified"]
    assert {run.rules[first["name"]]["Program"], run.rules[second["name"]]["Program"]} == {PY, base}
    rules_mod.deny_fetch(run, first["name"])
    assert set(run.rules) == {second["name"]}          # removing one does not take the other's way out


def test_deny_fetch_removes_the_rule_and_a_stand_in_of_it():
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    run.rules[name + "-new"] = run.view(name + "-new", Action="Allow", Program=PY)
    rules_mod.deny_fetch(run, name)
    assert run.rules == {}


def test_a_stand_in_that_will_not_go_does_not_keep_the_way_out_open():
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    run.rules[name + "-new"] = run.view(name + "-new", Action="Allow", Program=PY)
    real = run.op_Remove

    def remove(p):
        return (1, "", "denied") if p["Name"].endswith("-new") else real(p)
    run.op_Remove = remove
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.deny_fetch(run, name)
    assert name + "-new" in str(e.value) and "denied" in str(e.value)
    assert name not in run.rules          # the rule under its own name is the way out, and it is gone


@pytest.mark.parametrize("name", ["TDC-FW-0123456789ab", "TDC-FW-ISO-loopback", "TDC-FW-ISO-fetch-*",
                                  "TDC-FW-ISO-fetch-ZZZZZZZZZZZZ", "", None, 5])
def test_deny_fetch_takes_nothing_but_a_per_fetch_rule(name):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.deny_fetch(run, name)
    assert run.writes() == []


def test_forget_fetch_rules_clears_what_an_interrupted_run_left():
    run, settings = make()
    thorough(run, settings)
    stale = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    run.rules[FETCHER] = run.view(FETCHER, Action="Allow", Program=PY)      # the standing rule of an older version
    kept = rules_mod.block(run, image=IMAGE, ip="5.6.7.8", fetcher=PY)["rule_id"]
    removed, stuck = rules_mod.forget_fetch_rules(run)
    assert sorted(removed) == sorted([stale, FETCHER]) and stuck == []
    assert set(run.rules) == {kept}                       # the blocks stay
    assert rules_mod.forget_fetch_rules(run) == ([], [])


def test_forget_fetch_rules_keeps_going_past_one_that_will_not_go_and_names_it():
    """A way out a crash left behind is only findable here, so one that sticks must not stop the others."""
    run, settings = make()
    thorough(run, settings)
    first = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    second = rules_mod.allow_fetch(run, fetcher=PY, ip="5.6.7.8", port=443)["name"]
    real = run.op_Remove

    def remove(p):
        return (1, "", "denied") if p["Name"] == first else real(p)
    run.op_Remove = remove
    removed, stuck = rules_mod.forget_fetch_rules(run)
    assert removed == [second] and [s["rule_id"] for s in stuck] == [first]
    assert "denied" in stuck[0]["problem"] and first in run.rules and second not in run.rules


def test_a_removal_that_says_nothing_but_leaves_the_rule_is_still_stuck():
    """Remove is quiet about a rule it did not remove, so the read-back is what notices."""
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    run.op_Remove = lambda p: (0, "", "")                  # says yes, does nothing
    removed, stuck = rules_mod.forget_fetch_rules(run)
    assert removed == [] and [s["rule_id"] for s in stuck] == [name]
    assert "still there" in stuck[0]["problem"]


def test_leaving_isolated_removes_a_per_fetch_rule_that_was_still_open():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)
    rules_mod.isolate(run, False, settings=settings)
    assert run.rules == {}


# ---- the state at start ---------------------------------------------------------------------


def test_startup_with_nothing_to_say_says_nothing():
    run, settings = FakeRun(), FakeSettings()
    state = rules_mod.startup_state(run, settings)
    assert state == {"isolated": False, "profiles_off": [], "announce": False, "note": None, "allowed_out": None,
                     "stage": "open"}


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


# ---- a restart finds the cut and does not tidy it away ----------------------------------------
# A crash in stage ``cut`` leaves the cut rule standing and the default action not yet Block: the egress is shut by
# the rule alone. A restart that took that for a stale marker would clear it and orphan a catch-all Block.


def test_a_standing_cut_rule_is_enforcement_in_force_and_is_not_cleared():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    settings.set(isolated=True, outbound_before="Allow", stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "cut"
    assert settings.isolated is True                    # the marker is NOT cleared
    assert rules_mod.CUT_RULE in run.rules              # and the rule is NOT removed
    assert "cut" in state["note"].lower()
    assert state["announce"] is True
    assert run.writes() == []                           # no Allow rule switched on, nothing removed


def test_a_marker_with_neither_block_nor_a_cut_rule_is_still_stale():
    run, settings = make(foreign=STOCK)
    settings.set(isolated=True, outbound_before="Allow", stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and settings.isolated is False
    assert state["stage"] == "open" and settings.stage == "open"


def test_a_stale_marker_still_switches_back_on_what_it_switched_off():
    run, settings = make(foreign={DNS_RULE: {**STOCK[DNS_RULE], "Enabled": False}})
    settings.set(isolated=True, outbound_before="Allow", stage="cut", allow_disabled=[DNS_RULE])
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "open" and run.foreign[DNS_RULE]["Enabled"] is True


def test_a_cut_rule_without_a_marker_is_announced_and_left_alone():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    state = rules_mod.startup_state(run, settings)
    assert state["announce"] is True and rules_mod.CUT_RULE in run.rules
    assert "no ISOLATED marker" in state["note"] or "did not set" in state["note"]
    assert state["isolated"] is False and state["stage"] == "open"
    assert run.writes() == []


def test_a_cut_rule_without_a_marker_does_not_keep_the_rules_a_failed_leaving_left_off():
    # Block beats Allow, so switching them on again opens nothing; leaving them off would cost DNS and DHCP later
    run, settings = make(foreign={DNS_RULE: {**STOCK[DNS_RULE], "Enabled": False}})
    rules_mod.cut(run)
    settings.set(allow_disabled=[DNS_RULE])
    state = rules_mod.startup_state(run, settings)
    assert run.foreign[DNS_RULE]["Enabled"] is True and settings.allow_disabled == []
    assert rules_mod.CUT_RULE in run.rules and state["announce"] is True
    assert "no ISOLATED marker" in state["note"] and "switched on again" in state["note"]
    assert "Nothing was changed" not in state["note"]          # something was: the note must not say both
    assert state["isolated"] is False


def test_a_cut_rule_without_a_marker_and_nothing_to_reopen_says_nothing_was_changed():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    assert "Nothing was changed" in rules_mod.startup_state(run, settings)["note"]


def test_a_cut_rule_without_a_marker_says_which_rules_stay_off_when_one_will_not_come_on():
    run, settings = make(foreign={DNS_RULE: {**STOCK[DNS_RULE], "Enabled": False}}, stubborn=[DNS_RULE])
    rules_mod.cut(run)
    settings.set(allow_disabled=[DNS_RULE])
    note = rules_mod.startup_state(run, settings)["note"]
    assert DNS_RULE in note and "no ISOLATED marker" in note and settings.allow_disabled == [DNS_RULE]


def test_a_default_block_without_a_marker_still_leaves_the_rules_a_failed_leaving_left_off():
    run, settings = make(foreign={DNS_RULE: {**STOCK[DNS_RULE], "Enabled": False}}, outbound="Block")
    settings.set(allow_disabled=[DNS_RULE])
    rules_mod.startup_state(run, settings)
    assert run.foreign[DNS_RULE]["Enabled"] is False and settings.allow_disabled == [DNS_RULE]


def test_the_converged_stage_is_found_again_after_a_restart():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "isolated" and state["isolated"] is True
    assert rules_mod.CUT_RULE not in run.rules


def test_the_policy_stage_is_found_again_after_a_restart():
    run, settings = make(foreign=POLICY_STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "cut_policy" and state["isolated"] is True
    assert rules_mod.CUT_RULE in run.rules and "Lab proxy out" in state["note"]


def test_a_crash_after_block_but_before_the_cut_rule_fell_is_still_the_cut_stage():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    rules_mod.cut(run)                                   # the rule is back: the worker died before it was dropped
    settings.set(stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "cut" and rules_mod.CUT_RULE in run.rules


def test_a_cut_rule_over_some_profiles_blocking_is_still_in_force():
    run, settings = make(foreign=STOCK, outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    rules_mod.cut(run)
    settings.set(isolated=True, outbound_before="Allow", stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "cut" and settings.isolated is True
    assert rules_mod.CUT_RULE in run.rules


def test_a_cut_rule_does_not_shut_a_profile_whose_firewall_is_off_and_that_is_said():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    run.profiles["Public"] = False
    settings.set(isolated=True, outbound_before="Allow", stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and state["announce"] is True and state["profiles_off"] == ["Public"]
    assert settings.isolated is True and rules_mod.CUT_RULE in run.rules      # not cleared, not removed
    assert "Public" in state["note"] and run.writes() == []


def test_a_cut_rule_that_cannot_be_read_is_not_taken_for_gone():
    run, settings = make(foreign=STOCK, fail={"Get": (1, "denied")})
    settings.set(isolated=True, outbound_before="Allow", stage="cut", allow_disabled=[DNS_RULE])
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["announce"] is True and state["stage"] == "cut"
    assert settings.isolated is True and settings.allow_disabled == [DNS_RULE]
    assert run.writes() == []
    assert "cut" in state["note"].lower() and "not known" in state["note"]


def test_a_cut_rule_that_cannot_be_read_does_not_blur_a_default_that_is_in_force():
    run, settings = make(foreign=STOCK, outbound="Block", fail={"Get": (1, "denied")})
    settings.set(isolated=True, outbound_before="Allow", stage="isolated")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "isolated" and settings.isolated is True


# -- the derived stage is saved when it differs ---------------------------------------------


def test_the_stage_found_is_saved_when_it_differs_from_the_saved_one():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    settings.set(isolated=True, outbound_before="Allow", stage="isolated")      # the file says more than is true
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "cut" and settings.stage == "cut"
    assert run.writes() == [] and rules_mod.CUT_RULE in run.rules               # bookkeeping only


def test_the_stage_found_after_a_crash_between_the_marker_and_the_stage_is_saved():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    settings.set(isolated=True, outbound_before="Allow")                          # stage still "open"
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "cut" and settings.stage == "cut"


def test_a_stage_that_already_matches_is_not_written_again():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    settings.saved.clear()
    assert rules_mod.startup_state(run, settings)["stage"] == "isolated"
    assert settings.saved == []


def test_a_stage_that_cannot_be_saved_is_said_and_start_up_goes_on():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    settings.set(isolated=True, outbound_before="Allow", stage="isolated")
    settings.fail = True
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "cut" and settings.stage == "isolated"
    assert "could not be saved" in state["note"] and "disk full" in state["note"]
    assert rules_mod.CUT_RULE in run.rules and settings.isolated is True


def test_a_stage_that_is_only_recorded_is_not_rewritten_when_the_cut_rule_cannot_be_read():
    run, settings = make(foreign=STOCK, fail={"Get": (1, "denied")})
    settings.set(isolated=True, outbound_before="Allow", stage="cut_policy")
    settings.saved.clear()
    assert rules_mod.startup_state(run, settings)["stage"] == "cut_policy" and settings.saved == []


# -- a cut rule that is not a full cut is named, and left alone -------------------------------


def _narrowed(run):
    rules_mod.cut(run)
    run.rules[rules_mod.CUT_RULE].update(Program=r"C:\x\loader.exe")          # a Block for one program only


def test_a_narrowed_cut_rule_under_a_stale_marker_is_named_and_left_standing():
    run, settings = make(foreign=STOCK)
    _narrowed(run)
    settings.set(isolated=True, outbound_before="Allow", stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "open" and settings.isolated is False             # stale, as before
    assert rules_mod.CUT_RULE in run.rules and run.rules[rules_mod.CUT_RULE]["Program"] == r"C:\x\loader.exe"
    assert rules_mod.CUT_RULE in state["note"] and "not a full cut" in state["note"]
    assert "left alone" in state["note"] and rules_mod.UNISOLATE_SCRIPT in state["note"]
    assert state["announce"] is True and "RemoveIsolate" not in run.ops()


def test_a_disabled_cut_rule_without_a_marker_is_named_and_announced():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    run.rules[rules_mod.CUT_RULE]["Enabled"] = False
    state = rules_mod.startup_state(run, settings)
    assert state["announce"] is True and state["isolated"] is False
    assert rules_mod.CUT_RULE in state["note"] and "not a full cut" in state["note"] and "disabled" in state["note"]
    assert rules_mod.CUT_RULE in run.rules and run.writes() == []


def test_a_narrowed_cut_rule_is_not_taken_for_a_cut_that_was_dropped():
    run, settings = make(outbound="Block")           # nothing else lets traffic out: only the rule is in question
    _narrowed(run)
    settings.set(isolated=True, outbound_before="Allow", stage="isolated")
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "cut" and settings.stage == "cut"      # the rule is there: the cut is not dropped
    assert state["isolated"] is True and "not a full cut" in state["note"]


def test_no_cut_rule_at_all_names_nothing():
    run, settings = make(foreign=STOCK)
    assert rules_mod.startup_state(run, settings)["note"] is None


# -- the whole table: marker x Block x firewall off x cut rule -----------------------------------
# Every row is one reachable state at start-up. Whatever the row, a rule that was there is still there, unchanged, and
# nothing but the marker and the stage is written when the marker is cleared.

BLOCKS = {"none": "Allow", "some": {"Domain": "Block", "Private": "Allow", "Public": "Allow"}, "all": "Block"}
CUTS = ("absent", "full", "wrong", "unreadable")
# (block, off, cut) -> (isolated, marker kept, stage returned, stage saved after); the file said "cut_policy" before
MARKED = {
    ("none", False, "absent"): (False, False, "open", "open"),
    ("none", False, "full"): (True, True, "cut", "cut"),
    ("none", False, "wrong"): (False, False, "open", "open"),
    ("none", False, "unreadable"): (True, True, "cut_policy", "cut_policy"),
    ("none", True, "absent"): (False, False, "open", "open"),
    ("none", True, "full"): (False, True, "open", "open"),
    ("none", True, "wrong"): (False, False, "open", "open"),
    ("none", True, "unreadable"): (False, True, "open", "cut_policy"),
    ("some", False, "absent"): (False, True, "open", "open"),
    ("some", False, "full"): (True, True, "cut", "cut"),
    ("some", False, "wrong"): (False, True, "open", "open"),
    ("some", False, "unreadable"): (True, True, "cut_policy", "cut_policy"),
    ("some", True, "absent"): (False, True, "open", "open"),
    ("some", True, "full"): (False, True, "open", "open"),
    ("some", True, "wrong"): (False, True, "open", "open"),
    ("some", True, "unreadable"): (False, True, "open", "cut_policy"),
    ("all", False, "absent"): (True, True, "isolated", "isolated"),
    ("all", False, "full"): (True, True, "cut", "cut"),
    ("all", False, "wrong"): (True, True, "cut", "cut"),
    ("all", False, "unreadable"): (True, True, "cut_policy", "cut_policy"),
    ("all", True, "absent"): (False, True, "open", "open"),
    ("all", True, "full"): (False, True, "open", "open"),
    ("all", True, "wrong"): (False, True, "open", "open"),
    ("all", True, "unreadable"): (False, True, "open", "cut_policy"),
}


def _found(block, off, cut, *, marker, leftover=False):
    """The run and settings of one row; ``leftover`` adds one Allow rule a failed leaving left off."""
    foreign = {DNS_RULE: {**STOCK[DNS_RULE], "Enabled": False}} if leftover else None
    run = FakeRun(outbound=BLOCKS[block], foreign=foreign, fail={"Get": (1, "denied")} if cut == "unreadable" else None)
    settings = FakeSettings(isolated=marker, outbound_before="Allow" if marker else None,
                            stage="cut_policy" if marker else "open", allow_disabled=[DNS_RULE] if leftover else ())
    if cut in ("full", "wrong"):
        rules_mod.cut(run)
        if cut == "wrong":
            run.rules[rules_mod.CUT_RULE]["Enabled"] = False
    if off:
        run.profiles["Public"] = False
    return run, settings


@pytest.mark.parametrize("row", sorted(MARKED), ids=lambda r: "-".join(str(x) for x in r))
def test_every_state_a_restart_can_find_under_a_marker(row):
    block, off, cut = row
    isolated, kept, stage, saved = MARKED[row]
    run, settings = _found(block, off, cut, marker=True)
    before = {n: dict(v) for n, v in run.rules.items()}
    state = rules_mod.startup_state(run, settings)
    assert (state["isolated"], settings.isolated, state["stage"], settings.stage) == (isolated, kept, stage, saved)
    assert state["announce"] is True and state["note"]
    assert run.rules == before                                    # a rule that was there is there, as it was
    assert [o for o in run.ops() if o in ("Remove", "RemoveIsolate", "Create", "SetDefaultOutbound", "Enable")] == []
    if cut == "unreadable":
        assert "could not be read" in state["note"] and "not known" in state["note"]
    if cut == "wrong":
        assert "not a full cut" in state["note"] and "left alone" in state["note"]
    if isolated:
        assert "not a working isolation" not in state["note"]
    if not isolated and kept:
        assert "not a working isolation" in state["note"]


@pytest.mark.parametrize("cut", ["absent", "wrong", "unreadable"])
@pytest.mark.parametrize("block", ["none", "some", "all"])
def test_the_firewall_that_is_off_is_never_isolated_whatever_the_cut_rule_says(block, cut):
    run, settings = _found(block, True, cut, marker=True)
    assert rules_mod.startup_state(run, settings)["isolated"] is False


def test_an_unreadable_cut_rule_with_a_profile_off_says_so_and_does_not_claim_isolation():
    run, settings = _found("none", True, "unreadable", marker=True)
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is False and state["profiles_off"] == ["Public"]
    assert "not a working isolation" in state["note"] and "not known" in state["note"] and "Public" in state["note"]


def test_an_unreadable_cut_rule_with_some_profiles_blocking_is_believed_and_the_stage_kept():
    run, settings = _found("some", False, "unreadable", marker=True)
    settings.stage = "cut"
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and state["stage"] == "cut" and settings.stage == "cut"
    assert "not known" in state["note"] and "Domain" in state["note"] and "not a working isolation" not in state["note"]


# The one call that touches enforcement: Allow rules are switched back on only where that opens nothing.
REOPENED = {("none", False, "absent", True), ("none", False, "wrong", True), ("none", True, "absent", True),
            ("none", True, "wrong", True)}


@pytest.mark.parametrize("marker", [True, False])
@pytest.mark.parametrize("row", sorted(MARKED), ids=lambda r: "-".join(str(x) for x in r))
def test_leftover_allow_rules_are_switched_on_again_only_where_that_opens_nothing(row, marker):
    block, off, cut = row
    run, settings = _found(block, off, cut, marker=marker, leftover=True)
    rules_mod.startup_state(run, settings)
    if marker:
        reopens = (block, off, cut, True) in REOPENED
    else:
        reopens = block == "none" or cut == "full"
    assert run.foreign[DNS_RULE]["Enabled"] is reopens
    assert ("EnableAllowOut" in run.ops()) is reopens
    assert (settings.allow_disabled == []) is reopens


def test_a_stage_without_a_marker_is_not_a_stage():
    run, settings = make(foreign=STOCK)
    settings.set(stage="cut")
    state = rules_mod.startup_state(run, settings)
    assert state["stage"] == "open" and settings.stage == "open"
    assert state["announce"] is False and run.writes() == []


def test_a_stage_without_a_marker_that_cannot_be_forgotten_does_not_stop_start_up():
    run, settings = make(foreign=STOCK)
    settings.stage, settings.fail = "isolated", True
    assert rules_mod.startup_state(run, settings)["stage"] == "open"


def test_the_stage_of_a_marker_is_the_recorded_one_when_the_firewall_cannot_be_read():
    run = FakeRun(fail={"Profiles": (1, "denied")})
    settings = FakeSettings(isolated=True, outbound_before="Allow", stage="cut_policy")
    assert rules_mod.startup_state(run, settings)["stage"] == "cut_policy"
    assert rules_mod.startup_state(run, FakeSettings(stage="cut"))["stage"] == "open"


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
    assert "-DefaultOutboundAction $value" in text and "TDC-FW-*" in text
    # it opens: Allow, or the recorded value when that is Allow or NotConfigured, never Block
    assert "$value = if ($before[$n] -in @('Allow', 'NotConfigured')) { $before[$n] } else { 'Allow' }" in text
    assert "outbound_before" in text and "Set-NetFirewallProfile -PolicyStore PersistentStore" in text
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
    out = rules_mod.isolate(run, False, settings=settings)
    assert out["changed"] is False and "not isolating" in out["note"] and "tdc-unisolate" in out["note"]
    assert run.writes() == [] and set(run.outbound.values()) == {"Block"}


def test_isolating_from_a_baseline_that_is_already_block_and_leaving_it_back_to_block():
    run, settings = make(outbound="Block")
    thorough(run, settings)
    assert settings.isolated is True and settings.outbound_before == "Block"
    assert run.rules == {}
    assert rules_mod.startup_state(run, settings)["isolated"] is True
    out = rules_mod.isolate(run, False, settings=settings)
    assert out["isolated"] is False and set(run.outbound.values()) == {"Block"} and run.rules == {}
    assert "baseline" in out["note"] and "not a TDC lockout" in out["note"] and "Domain, Private, Public" in out["note"]
    assert settings.isolated is False and settings.outbound_before is None


def test_leaving_to_a_baseline_that_is_open_has_nothing_to_explain():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    assert rules_mod.isolate(run, False, settings=settings)["note"] is None


def test_a_mixed_baseline_names_the_profiles_that_stay_shut():
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    thorough(run, settings)
    out = rules_mod.isolate(run, False, settings=settings)
    assert "Block on Domain:" in out["note"]


def test_a_marker_without_a_baseline_says_it_assumed_allow():
    run, settings = FakeRun(outbound="Block"), FakeSettings(isolated=True, outbound_before=None)
    assert "assumed" in rules_mod.isolate(run, False, settings=settings)["note"]


# ---- several rules, one key ------------------------------------------------------------------


def test_two_rules_that_share_a_key_come_back_as_two_entries_with_their_own_protocol():
    run = FakeRun()
    tcp = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    udp = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="udp", fetcher=PY)
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


def test_replacing_a_per_fetch_rule_never_leaves_the_fetcher_without_one():
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    run.rules[name]["RemoteAddress"] = ["9.9.9.9"]           # someone changed it under us
    run.standing.clear()
    assert rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["verified"] is True
    assert run.standing and all(any(a == "Allow" and prog == PY for _, a, prog in moment) for moment in run.standing)
    assert run.rules[name]["RemoteAddress"] == ["1.2.3.4"] and name + "-new" not in run.rules


def test_the_loopback_rule_an_older_version_left_goes_when_isolated_is_left():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    for name in (LOOPBACK, LOOPBACK + "-new"):
        run.rules[name] = run.view(name, Action="Allow", RemoteAddress=["127.0.0.0/8"])
    thorough(run, settings)
    assert "Create" not in run.ops()                      # isolating again does not rewrite it either
    rules_mod.isolate(run, False, settings=settings)
    assert run.rules == {} and settings.isolated is False


def test_an_isolate_rule_that_will_not_go_is_said_and_keeps_the_marker():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    run.rules[LOOPBACK] = run.view(LOOPBACK, Action="Allow")
    run.stuck_rules = {LOOPBACK}
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, False, settings=settings)
    assert LOOPBACK in str(e.value) and settings.isolated is True


def test_the_stand_in_goes_with_isolated_and_can_be_unblocked_by_hand():
    run, settings = make(outbound="Allow")
    thorough(run, settings)
    run.rules[FETCHER + "-new"] = run.view(FETCHER + "-new", Action="Allow", Program=PY)
    rules_mod.isolate(run, False, settings=settings)
    assert run.rules == {}
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.rules[r["rule_id"] + "-new"] = run.view(r["rule_id"] + "-new")
    rules_mod.unblock(run, r["rule_id"] + "-new")
    assert r["rule_id"] + "-new" not in run.rules


def test_replacing_a_block_does_not_open_a_gap_either():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.rules[first["rule_id"]]["Enabled"] = False
    run.standing.clear()
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    assert all(any(a == "Block" and prog == IMAGE for _, a, prog in moment) for moment in run.standing)


# ---- the lockout targets ---------------------------------------------------------------------


LOCAL_ONLY = ["127.0.0.1", "127.8.9.1", "::1", "0.0.0.0", "::", "224.0.0.251", "239.255.255.250", "ff02::fb", "::ffff:127.0.0.1"]


@pytest.mark.parametrize("ip", LOCAL_ONLY)
def test_a_block_for_every_program_on_an_address_that_would_cut_tdc_off_from_itself_is_refused(ip):
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, ip=ip, fetcher=PY)
    assert run.calls == []


LOOPBACK_ADDRESSES = ["127.0.0.1", "127.8.9.1", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1"]
MULTICAST_UNSPECIFIED = ["0.0.0.0", "::", "224.0.0.251", "239.255.255.250", "ff02::fb", "::ffff:224.0.0.251"]


@pytest.mark.parametrize("ip", MULTICAST_UNSPECIFIED)
def test_a_block_that_names_a_program_may_cut_that_programs_multicast(ip):
    """mDNS and SSDP are multicast, which Windows does filter: a program-scoped block on them bites."""
    run = FakeRun()
    r = rules_mod.block(run, image=IMAGE, ip=ip, fetcher=PY)
    assert r["verified"] is True and r["ip"] == ip.replace("::ffff:", "")
    assert "-Program" in " ".join(run.calls[0])


@pytest.mark.parametrize("ip", LOOPBACK_ADDRESSES)
@pytest.mark.parametrize("image", [IMAGE, None])
def test_a_block_on_loopback_is_refused_for_one_program_and_for_all(ip, image):
    """Windows does not filter loopback: the rule would stand, read back, be called verified, and block nothing
    (seen on the VM: curl to 127.0.0.1 still answered 200 under a 'verified' rule)."""
    run = FakeRun()
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(run, image=image, ip=ip, port=9000 if image else None, protocol="tcp" if image else None, fetcher=PY)
    assert run.calls == []


def test_the_loopback_refusal_says_why():
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(FakeRun(), image=IMAGE, ip="::ffff:127.0.0.1", fetcher=PY)
    text = str(e.value)
    assert "127.0.0.1 is a loopback address" in text and "does not filter loopback" in text
    assert "block nothing" in text and "KILL" in text


def test_a_loopback_rule_left_by_an_earlier_version_is_never_called_a_block():
    run = FakeRun()
    name = "TDC-FW-0123456789ab"
    run.rules[name] = run.view(name, Action="Block", Program=IMAGE, RemoteAddress=["127.0.0.1"])
    listed = rules_mod.rules(run)
    assert [(r["rule_id"], r["blocking"]) for r in listed] == [(name, False)]
    assert rules_mod.verify(run, name) is False
    run.rules[name]["RemoteAddress"] = ["1.2.3.4"]
    assert rules_mod.rules(run)[0]["blocking"] is True and rules_mod.verify(run, name) is True


def test_the_fetcher_is_required_and_none_is_the_explicit_opt_out():
    run = FakeRun()
    with pytest.raises(TypeError):
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert run.calls == []
    assert rules_mod.block(run, image=PY, ip="1.2.3.4", fetcher=None)["verified"] is True


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


def test_every_binary_the_fetch_may_run_as_is_refused_as_a_block_target():
    run = FakeRun()
    base = r"C:\Python312\python.exe"
    for image in (PY, base, base.upper()):
        with pytest.raises(rules_mod.RuleError) as e:
            rules_mod.block(run, image=image, ip="1.2.3.4", fetcher=(PY, base))
        assert "fetcher" in str(e.value)
    assert run.calls == []
    assert rules_mod.block(run, image=IMAGE, fetcher=[PY, base])["verified"] is True
    for bad in ("", "-x", 5, [PY, ""], [PY, None]):
        with pytest.raises(rules_mod.RuleError):
            rules_mod.block(FakeRun(), image=IMAGE, fetcher=bad)


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
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    rules_mod.kill(run, 4812)
    assert all(ntpath.isabs(c[0]) for c in run.calls)


@pytest.mark.parametrize("port", ["\u0664\u0664\u0663", "\uff14\uff14\uff13", "\u00b2"])
def test_a_port_in_other_digits_is_refused(port):
    with pytest.raises(rules_mod.RuleError):
        rules_mod.block(FakeRun(), ip="1.2.3.4", port=port, protocol="tcp", fetcher=PY)


def test_a_port_in_ascii_digits_as_text_still_works():
    assert rules_mod.block(FakeRun(), ip="1.2.3.4", port="443", protocol="tcp", fetcher=PY)["port"] == 443


# ---- the two halves agree on the names -------------------------------------------------------


def test_every_parameter_the_module_emits_is_declared_by_the_script():
    script = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    block_text = re.search(r"^param\((.*?)^\)", script, re.S | re.M).group(1)
    declared = set(re.findall(r"\$(\w+)\s*[,\n]", block_text + "\n"))
    assert {"Op", "Name", "Program", "RemoteAddress", "RemotePort", "Protocol", "Action", "Profiles",
            "DefaultOutboundAction"} <= declared
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    rules_mod.block(run, image=IMAGE, ip="1.2.3.4", port=443, protocol="tcp", fetcher=PY)
    rules_mod.block(run, image=IMAGE, fetcher=PY)
    rules_mod.rules(run)
    rules_mod.enable_firewall(run)
    thorough(run, settings)
    rules_mod.isolate(run, False, settings=settings)
    emitted = set()
    for call in run.calls:
        if ntpath.basename(call[0]).lower() == "powershell.exe":
            rest = call[call.index("-File") + 2:]
            emitted |= {rest[i][1:] for i in range(0, len(rest), 2)}
            assert all(rest[i].startswith("-") for i in range(0, len(rest), 2))
    assert {"Profiles", "RemotePort", "Protocol", "Program", "RemoteAddress", "DefaultOutboundAction"} <= emitted
    assert emitted <= declared, emitted - declared


# ---- a failed replacement says what stands -------------------------------------------------


def test_a_block_whose_replacement_fails_says_the_stand_in_is_standing():
    run = FakeRun()
    first = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    run.rules[first["rule_id"]]["Enabled"] = False
    real = run.op_Create
    seen = {"n": 0}

    def create(p):
        seen["n"] += 1
        return (1, "", "denied") if seen["n"] == 3 else real(p)      # the exists check, the stand-in, then the new rule fails
    run.op_Create = create
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)
    text = str(e.value)
    assert first["rule_id"] + "-new" in text and "standing in" in text and "denied" in text
    assert run.rules[first["rule_id"] + "-new"]["Enabled"] is True
    assert first["rule_id"] not in run.rules
    assert [x["blocking"] for x in rules_mod.rules(run)] == [True]          # the stand-in blocks, and rules() says so


# ---- a damaged marker ----------------------------------------------------------------------


def test_a_marker_without_a_baseline_gets_allow_and_the_note_says_tdc_shut_it():
    run, settings = make(outbound="Block")
    settings.isolated, settings.outbound_before, settings.isolated_since = True, None, 123.0
    out = thorough(run, settings)
    assert settings.outbound_before == "Allow" and out["outbound_before"] == "Allow"
    assert "no recorded baseline" in out["note"] and "because TDC shut it" in out["note"]
    assert settings.isolated_since == 123.0
    left = rules_mod.isolate(run, False, settings=settings)
    assert set(run.outbound.values()) == {"Allow"} and left["note"] is None


def test_a_failure_with_a_damaged_marker_is_not_rolled_back_to_open():
    run, settings = make(outbound="Block", fail={"Cut": (1, "denied")})
    settings.isolated, settings.outbound_before = True, None
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, settings=settings)
    assert "scripts/tdc-unisolate.ps1" in str(e.value)
    assert settings.isolated is True and set(run.outbound.values()) == {"Block"} and "RemoveIsolate" not in run.ops()


# ---- Windows' own outbound Allow rules: DefaultOutboundAction Block does not stop them ------------


def test_isolated_switches_off_windows_own_allow_rules_and_leaving_switches_exactly_those_on():
    run, settings = make(foreign={**STOCK, **{}})
    out = thorough(run, settings)
    assert run.enabled_foreign() == []                                   # DNS and DHCP are off now
    assert sorted(settings.allow_disabled) == ["CoreNet-DHCP-Out", DNS_RULE]   # Teredo was off already: not recorded
    assert out["verified"] is True and out["allowed_out"] == [] and out["note"] is None
    left = rules_mod.isolate(run, False, settings=settings)
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE] and run.foreign["CoreNet-Teredo-Out"]["Enabled"] is False
    assert settings.allow_disabled == [] and left["allow_disabled"] == [] and left["note"] is None


def test_the_rule_names_are_saved_before_anything_changes_and_closed_before_block():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    kinds = [t[0] for t in run.timeline]
    first_write = min(i for i, k in enumerate(kinds) if k in ("Create", "Cut", "DisableAllowOut", "SetDefaultOutbound"))
    assert kinds[first_write - 1] == "settings" and "outbound_before" in settings.saved[0]       # before the cut
    assert kinds[first_write] == "Cut"
    names = next(i for i, (k, v) in enumerate(run.timeline) if k == "settings" and "allow_disabled" in v)
    assert kinds.index("AllowOut") < names < kinds.index("DisableAllowOut")      # read, noted, only then switched off
    assert "Create" not in kinds and kinds.index("DisableAllowOut") < kinds.index("SetDefaultOutbound")
    assert kinds.index("SetDefaultOutbound") < len(kinds) - 1 - kinds[::-1].index("AllowOut")      # and read back after
    run.timeline.clear()
    rules_mod.isolate(run, False, settings=settings)
    kinds = [t[0] for t in run.timeline]
    assert kinds.index("SetDefaultOutbound") < kinds.index("EnableAllowOut") < kinds.index("RemoveIsolate") < kinds.index("settings")


def test_a_rule_a_group_policy_sets_cannot_be_closed_and_is_said_never_hidden():
    run, settings = make(foreign={**STOCK, **GPO_RULE})
    out = thorough(run, settings)
    assert out["stage"] == "cut_policy" and [r["name"] for r in out["allowed_out"]] == ["{gpo-1}"]
    assert out["verified"] is True and rules_mod.CUT_RULE in run.rules      # the cut rule is what closes it, read back
    assert out["allowed_out"][0]["source"] == "GroupPolicy" and out["allowed_out"][0]["local"] is False
    assert "Lab proxy out" in out["note"] and "group policy" in out["note"]
    assert "{gpo-1}" not in settings.allow_disabled and settings.isolated is True


def test_a_cut_rule_that_cannot_be_read_back_is_not_called_standing_in_the_policy_stage():
    run, settings = make(foreign={**STOCK, **GPO_RULE})
    rules_mod.isolate(run, True, settings=settings)
    run.rules[rules_mod.CUT_RULE]["Enabled"] = False                       # something disabled it behind our back
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut_policy" and done["verified"] is False and "not known" in done["note"]


def test_a_local_rule_that_will_not_switch_off_stays_in_the_read_back():
    run, settings = make(foreign=STOCK, stubborn={DNS_RULE})
    out = thorough(run, settings)
    assert out["stage"] == "cut_policy" and [r["name"] for r in out["allowed_out"]] == [DNS_RULE]
    assert "Core Networking - DNS (UDP-Out)" in out["note"] and settings.isolated is True
    assert rules_mod.CUT_RULE in run.rules


def test_converging_switches_nothing_off_when_windows_own_rules_cannot_be_read():
    run, settings = make(foreign=STOCK, fail={"AllowOut": (1, "access denied")})
    rules_mod.isolate(run, True, settings=settings)           # the cut does not need that list
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and "could not be read" in done["note"] and "access denied" in done["note"]
    assert "DisableAllowOut" not in run.ops() and "SetDefaultOutbound" not in run.ops()
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE] and rules_mod.CUT_RULE in run.rules
    assert settings.allow_disabled == []


def test_nothing_is_cut_when_the_profiles_cannot_be_read():
    run, settings = make(foreign=STOCK, fail={"Profiles": (1, "access denied")})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, settings=settings)
    assert "nothing was changed" in str(e.value) and "access denied" in str(e.value)
    assert run.rules == {} and settings.saved == [] and "Cut" not in run.ops()


def test_converging_switches_nothing_off_when_the_rule_names_cannot_be_saved():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    settings.fail = True
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and "no rule was switched off" in done["note"]
    assert "DisableAllowOut" not in run.ops() and rules_mod.CUT_RULE in run.rules
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]


def test_converge_refuses_when_the_marker_is_gone():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.isolate(run, False, settings=settings)               # a leave came first
    run.calls.clear()
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["refused"] is True and done["stage"] == "open" and "no marker" in done["note"]
    assert run.ops() == [] and run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]    # not one call, not one rule off
    assert set(run.outbound.values()) == {"Allow"} and settings.allow_disabled == []


def test_a_converge_that_runs_is_not_refused():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    assert rules_mod.converge(run, settings=settings, cancelled=lambda: False)["refused"] is False


def test_a_rule_that_came_back_on_is_recorded_by_the_next_converge():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    run.foreign["CoreNet-Teredo-Out"]["Enabled"] = True            # a policy refresh switched one on again
    rules_mod.isolate(run, True, settings=settings)                # cut again: the press records nothing
    assert "CoreNet-Teredo-Out" not in settings.allow_disabled
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert "CoreNet-Teredo-Out" in settings.allow_disabled and run.enabled_foreign() == []


def test_a_read_back_that_fails_is_unknown_and_keeps_the_cut_rule():
    run, settings = make(foreign=STOCK)
    real = run.op_AllowOut
    seen = {"n": 0}

    def allow_out(p):
        seen["n"] += 1
        return real(p) if seen["n"] == 1 else (1, "", "rpc failed")
    run.op_AllowOut = allow_out
    out = thorough(run, settings)
    assert out["stage"] == "cut_policy" and out["allowed_out"] is None and "rpc failed" in out["allowed_out_error"]
    assert "rpc failed" in out["note"] and rules_mod.CUT_RULE in run.rules      # what is not known never drops the cut
    assert out["verified"] is True      # the cut rule was read back, and it closes the egress with or without that list


def test_a_rule_that_will_not_switch_on_again_stays_recorded_and_is_retried():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    run.stubborn = {DNS_RULE}
    out = rules_mod.isolate(run, False, settings=settings)
    assert settings.isolated is False and settings.allow_disabled == [DNS_RULE] and out["allow_disabled"] == [DNS_RULE]
    assert DNS_RULE in out["note"] and "tdc-unisolate" in out["note"]
    run.stubborn = set()
    again = rules_mod.isolate(run, False, settings=settings)               # no marker: only the leftover is retried
    assert again["changed"] is True and settings.allow_disabled == [] and run.foreign[DNS_RULE]["Enabled"] is True
    assert set(run.outbound.values()) == {"Allow"}


def test_a_recorded_rule_that_is_gone_is_not_missed():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    del run.foreign[DNS_RULE]
    out = rules_mod.isolate(run, False, settings=settings)
    assert settings.allow_disabled == [] and out["note"] is None


def test_isolating_again_closes_a_rule_that_was_switched_on_meanwhile():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    run.foreign["CoreNet-Teredo-Out"]["Enabled"] = True                   # someone (or something) switched it on
    out = thorough(run, settings)
    assert out["verified"] is True and "CoreNet-Teredo-Out" in settings.allow_disabled
    rules_mod.isolate(run, False, settings=settings)
    assert run.enabled_foreign() == sorted(["CoreNet-DHCP-Out", "CoreNet-Teredo-Out", DNS_RULE])


def test_a_stale_marker_at_start_switches_the_recorded_rules_on_again():
    run = FakeRun(outbound="Allow", foreign={DNS_RULE: dict(STOCK[DNS_RULE], Enabled=False)})
    settings = FakeSettings(isolated=True, outbound_before="Allow", allow_disabled=[DNS_RULE])
    state = rules_mod.startup_state(run, settings)
    assert run.foreign[DNS_RULE]["Enabled"] is True and settings.allow_disabled == [] and settings.isolated is False
    assert state["announce"] is True


def test_isolated_found_at_start_says_what_still_gets_out():
    run = FakeRun(outbound="Block", foreign=GPO_RULE)
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(run, settings)
    assert state["isolated"] is True and [r["name"] for r in state["allowed_out"]] == ["{gpo-1}"]
    assert "Lab proxy out" in state["note"] and run.writes() == []


def test_many_rule_names_travel_in_several_calls_each_as_base64_never_as_text():
    names = {f"{{{i:08d}-aaaa-bbbb-cccc-dddddddddddd}} *weird, name": {"DisplayName": f"App {i}", "Source": "Local", "Enabled": True}
             for i in range(400)}
    run, settings = make(foreign=names)
    assert thorough(run, settings)["verified"] is True
    calls = [c for c in run.calls if FakeRun.params(c)["Op"] == "DisableAllowOut"]
    assert len(calls) > 1
    for call in calls:
        value = FakeRun.params(call)["Names"]
        assert re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) and len(value) <= rules_mod.ALLOW_OUT_CHUNK
        assert not any("weird" in a for a in call)
    assert run.enabled_foreign() == []


def test_the_script_switches_only_local_outbound_allow_rules_that_are_not_ours():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    body = text[text.index("function Set-AllowOut"):]
    body = body[:body.index("\n}\n")]
    assert "-PolicyStore PersistentStore" in body and "'Outbound'" in body and "'Allow'" in body
    assert "TDC-FW-" in text[text.index("function Get-NameList"):text.index("function Set-AllowOut")]
    assert "FromBase64String" in text and "-Name $" not in body


def test_the_hatch_switches_the_recorded_rules_on_again():
    text = open(os.path.join(ROOT, "scripts", "tdc-unisolate.ps1"), encoding="utf-8").read()
    assert "firewall_state.json" in text and "allow_disabled" in text and "Enable-NetFirewallRule" in text
    assert "PersistentStore" in text and "Invoke-Expression" not in text


def test_sysmon_logs_the_connections_curl_bits_and_tdc_python_make():
    """The upstream config's NetworkConnect is an include list without curl.exe, svchost.exe (BITS) or python.exe:
    a curl or BITS download could never become a finding, and tdc-anomaly could never fire."""
    script = open(os.path.join(ROOT, "scripts", "install-sysmon.ps1"), encoding="utf-8").read()
    body = script[script.index("function Set-NetworkConnectIncludes"):]
    body = body[:body.index("\n}\n")]
    for image in ("'curl.exe'", "'python.exe'", r"'C:\Windows\System32\svchost.exe'"):
        assert image in body
    assert "NetworkConnect[@onmatch='include']" in body
    # outbound only: an accepted connection (the analyst's browser on 9000) must not become a TDC python flow
    assert "'Initiated'" in body and "'true'" in body and "groupRelation', 'and'" in body
    calls = [m.start() for m in re.finditer(r"Set-NetworkConnectIncludes -Path \$configPath", script)]
    assert len(calls) == 2
    assert script.index("-c $configPath") > calls[0] and script.rindex("-i $configPath") > calls[-1]


def test_a_json_list_is_unrolled_the_way_windows_powershell_5_1_needs():
    """5.1 emits a JSON array from ConvertFrom-Json as one object: @(ConvertFrom-Json ...) is then a list of one
    list, and every DisableAllowOut / EnableAllowOut call fails. Parenthesised first, it unrolls in 5.1 and 7."""
    for path in (os.path.join(ROOT, "webui", "firewall_rules.ps1"), os.path.join(ROOT, "scripts", "tdc-unisolate.ps1")):
        text = open(path, encoding="utf-8").read()
        assert not re.search(r"@\(\s*ConvertFrom-Json", text), path
    script = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    assert "@((ConvertFrom-Json -InputObject $json))" in script


# ---- a button, not a minute: one PowerShell call per step --------------------------------------


def test_the_press_is_two_powershell_calls_the_convergence_six_and_off_three_however_many_rules():
    names = {f"App-{i:03d}-Out": {"DisplayName": f"App {i}", "Source": "Local", "Enabled": True} for i in range(135)}
    run, settings = make(foreign=names)
    pressed = rules_mod.isolate(run, True, settings=settings)
    assert pressed["verified"] is True and pressed["profiles_off"] == []
    assert run.ops() == ["Profiles", "Cut"]
    run.calls.clear()
    out = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert out["verified"] is True and out["allowed_out"] == []
    assert run.ops() == ["AllowOut", "DisableAllowOut", "SetDefaultOutbound", "AllowOut", "Remove", "Get"]
    run.calls.clear()
    left = rules_mod.isolate(run, False, settings=settings)
    assert run.ops() == ["SetDefaultOutbound", "EnableAllowOut", "RemoveIsolate"] and left["profiles_off"] == []
    assert len(run.enabled_foreign()) == 135


def test_a_mixed_baseline_is_put_back_in_one_call_per_value():
    run, settings = make(outbound={"Domain": "Block", "Private": "Allow", "Public": "Allow"})
    thorough(run, settings)
    run.calls.clear()
    rules_mod.isolate(run, False, settings=settings)
    sets = [FakeRun.params(c) for c in run.calls if FakeRun.params(c)["Op"] == "SetDefaultOutbound"]
    assert sorted((s["Profiles"], s["DefaultOutboundAction"]) for s in sets) == [("Domain", "Block"), ("Private,Public", "Allow")]
    assert run.outbound == {"Domain": "Block", "Private": "Allow", "Public": "Allow"}


def test_a_default_action_answer_without_the_profiles_is_read_back_separately():
    run, settings = make()
    rules_mod.isolate(run, True, settings=settings)
    real = run.op_SetDefaultOutbound
    run.op_SetDefaultOutbound = lambda p: (real(p)[0], "", "")      # an answer that is not the profiles
    run.calls.clear()
    assert rules_mod.converge(run, settings=settings, cancelled=lambda: False)["verified"] is True
    assert run.ops().count("Profiles") == 1


def test_the_script_switches_the_rules_in_one_pipeline_and_retries_only_the_ones_it_missed():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    body = text[text.index("function Set-AllowOut"):]
    body = body[:body.index("\n}\n")]
    assert "$found | Disable-NetFirewallRule -PassThru" in body and "$found | Enable-NetFirewallRule -PassThru" in body
    assert "$took.ContainsKey($name)" in body and "-ErrorAction Stop" in body
    remove = text[text.index("function Remove-IsolateRules"):]
    assert "Get-IsolateRules" in remove and "still" in remove
    assert "'ObjectNotFound'" in text[text.index("function Get-IsolateRules"):text.index("function Remove-IsolateRules")]


# ---- what is configured is put back, not what is in force ---------------------------------------


def test_a_baseline_of_not_configured_comes_back_as_not_configured_not_allow():
    """In force, NotConfigured reads Allow; remembering that and writing it back would leave the host configured
    differently from how it was found. The baseline is the configured value, and the write is checked there."""
    run, settings = make(foreign=STOCK, outbound="NotConfigured")
    assert {r["DefaultOutboundAction"] for r in run.profile_rows()} == {"Allow"}       # as in force
    on = thorough(run, settings)
    assert settings.outbound_before == "NotConfigured" and on["outbound_before"] == "NotConfigured"
    assert on["verified"] is True and set(run.outbound.values()) == {"Block"}
    assert rules_mod.startup_state(run, settings)["isolated"] is True                  # in force: Block
    left = rules_mod.isolate(run, False, settings=settings)
    assert run.outbound == {"Domain": "NotConfigured", "Private": "NotConfigured", "Public": "NotConfigured"}
    assert left["outbound_after"] == run.outbound and left["note"] is None
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]


def test_a_mixed_configured_baseline_comes_back_profile_by_profile():
    run, settings = make(outbound={"Domain": "NotConfigured", "Private": "Allow", "Public": "Block"})
    thorough(run, settings)
    assert settings.outbound_before == "Domain=NotConfigured,Private=Allow,Public=Block"
    rules_mod.isolate(run, False, settings=settings)
    assert run.outbound == {"Domain": "NotConfigured", "Private": "Allow", "Public": "Block"}


def test_block_that_a_group_policy_keeps_from_force_is_not_isolated():
    run, settings = make(outbound="NotConfigured")
    run.forced = {"Public": "Allow"}                         # configured Block, but a policy keeps Allow in force
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and done["verified"] is False and "Public" in done["note"]
    assert rules_mod.CUT_RULE in run.rules and settings.isolated is True        # the cut closes it; nothing was rolled back
    assert settings.outbound_before == "NotConfigured"


def test_the_script_reads_the_configured_value_where_it_writes_it():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    states = text[text.index("function Get-ProfileStates"):]
    states = states[:states.index("\n}\n")]
    assert "Get-NetFirewallProfile -PolicyStore PersistentStore" in states and "Get-NetFirewallProfile -PolicyStore ActiveStore" in states
    assert "Configured = " in states
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore -Profile" in text


# ---- the cut: one catch-all outbound Block rule, written and read back in one call -----------


def test_the_cut_is_one_call_that_writes_and_reads_back():
    run = FakeRun()
    done = rules_mod.cut(run)
    assert done == {"rule_id": "TDC-FW-ISO-cut", "verified": True, "problem": None, "profiles_off": []}
    assert run.ops() == ["Cut"]          # one PowerShell call, not four


def test_the_cut_rule_is_outbound_block_for_every_program_and_address():
    run = FakeRun()
    rules_mod.cut(run)
    view = run.rules["TDC-FW-ISO-cut"]
    assert (view["Direction"], view["Action"], view["Enabled"]) == ("Outbound", "Block", True)
    assert (view["Program"], view["RemoteAddress"], view["Protocol"]) == ("Any", ["Any"], "Any")


def test_the_cut_refuses_while_a_profile_is_off_and_writes_nothing():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": True})
    with pytest.raises(rules_mod.ProfileOffError) as e:
        rules_mod.cut(run)
    assert "Private" in str(e.value)
    assert run.rules == {}


def test_a_cut_rule_that_does_not_read_back_enabled_is_not_verified():
    run = FakeRun(disable_new=True)
    done = rules_mod.cut(run)
    assert done["verified"] is False and "disabled" in done["problem"]


def test_a_cut_rule_that_is_not_there_when_read_back_is_not_verified():
    run = FakeRun(get_rule_returns="")
    done = rules_mod.cut(run)
    assert done["verified"] is False and "not there" in done["problem"]


def test_a_cut_rule_that_reads_back_as_something_else_is_not_verified():
    run = FakeRun(rule_list=["TDC-FW-ISO-cut"], repair_fails=True)   # blocks one program, not everything
    run.rules["TDC-FW-ISO-cut"]["Program"] = IMAGE
    done = rules_mod.cut(run)
    assert done["verified"] is False and "every program and address" in done["problem"]


def test_a_cut_rule_that_covers_only_some_profiles_is_not_verified():
    run = FakeRun(rule_list=["TDC-FW-ISO-cut"], repair_fails=True)
    run.rules["TDC-FW-ISO-cut"]["Profile"] = "Domain, Private"
    done = rules_mod.cut(run)
    assert done["verified"] is False and "Public" in done["problem"]


def test_cutting_twice_leaves_one_rule_and_stays_verified():
    run = FakeRun()
    rules_mod.cut(run)
    done = rules_mod.cut(run)
    assert done["verified"] is True
    assert [n for n in run.rules] == ["TDC-FW-ISO-cut"]


@pytest.mark.parametrize("fail", [{"Cut": (1, "access is denied")}, {"Cut": (4, "")}, {"Cut": (127, "no powershell")}])
def test_a_cut_that_fails_raises_and_claims_nothing(fail):
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.cut(FakeRun(fail=fail))
    assert not isinstance(e.value, rules_mod.ProfileOffError)


def test_a_cut_whose_answer_cannot_be_read_raises():
    with pytest.raises(rules_mod.RuleError):
        rules_mod.cut(FakeRun(get_rule_returns="not json"))


def test_the_cut_takes_no_parameter_from_outside():
    run = FakeRun()
    rules_mod.cut(run)
    call = run.calls[0]
    assert call[call.index("-File") + 2:] == ["-Op", "Cut"]
    assert "-Command" not in call


def test_uncut_removes_it_and_says_so():
    run = FakeRun()
    rules_mod.cut(run)
    assert rules_mod.uncut(run) == {"removed": True, "problem": None}
    assert run.rules == {}


def test_uncut_without_a_rule_is_not_an_error():
    assert rules_mod.uncut(FakeRun()) == {"removed": True, "problem": None}


def test_uncut_says_when_the_rule_is_still_there():
    run = FakeRun()
    rules_mod.cut(run)
    run.op_Remove = lambda p: (0, "", "")              # Remove is quiet about a rule it did not remove
    done = rules_mod.uncut(run)
    assert done["removed"] is False and "still there" in done["problem"]


def test_uncut_that_fails_says_so_instead_of_raising():
    run = FakeRun(fail={"Remove": (1, "access is denied")})
    done = rules_mod.uncut(run)
    assert done["removed"] is False and "access is denied" in done["problem"]


def test_cut_stands_reads_the_rule_and_fails_closed():
    run = FakeRun()
    assert rules_mod.cut_stands(run) is False
    rules_mod.cut(run)
    assert rules_mod.cut_stands(run) is True
    assert rules_mod.cut_stands(FakeRun(fail={"Get": (1, "no")})) is None


def test_a_disabled_cut_rule_does_not_stand():
    run = FakeRun(disable_new=True)
    rules_mod.cut(run)
    assert rules_mod.cut_stands(run) is False


def test_the_cut_branch_of_the_script_names_no_parameter_and_one_rule():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    branch = text[text.index("'Cut' {"):]
    branch = branch[:branch.index("\n        }\n")]
    assert "TDC-FW-ISO-cut" in branch and "Assert-OurName" in branch
    assert "exit 3" in branch and "exit 4" not in branch
    assert "Get-ProfileStates" in branch and "Get-RuleView" in branch
    assert not re.search(r"\$(Name|Program|RemoteAddress|RemotePort|Protocol|Action)\b", branch)


# ---- the cut repairs a rule of its name that is not the catch-all, in place and in the same call ----


class WatchedRules(dict):
    """The rules of a FakeRun, noting every moment a rule is taken away: a gap in the egress block."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.removed = []

    def pop(self, key, *default):
        self.removed.append(key)
        return super().pop(key, *default)

    def __delitem__(self, key):
        self.removed.append(key)
        super().__delitem__(key)


def _standing_cut(**changes):
    run = FakeRun(rule_list=["TDC-FW-ISO-cut"])
    run.rules["TDC-FW-ISO-cut"].update(changes)
    run.rules = WatchedRules(run.rules)
    return run


def test_a_disabled_cut_rule_is_enabled_again_by_the_cut():
    run = _standing_cut(Enabled=False)
    assert rules_mod.cut_stands(run) is False
    run.calls.clear()
    done = rules_mod.cut(run)
    assert done == {"rule_id": "TDC-FW-ISO-cut", "verified": True, "problem": None, "profiles_off": []}
    assert run.rules["TDC-FW-ISO-cut"]["Enabled"] is True
    assert run.ops() == ["Cut"]                        # the repair is in the same single call


@pytest.mark.parametrize("changes", [
    {"Program": IMAGE},
    {"RemoteAddress": ["1.2.3.4"]},
    {"RemotePort": ["443"], "Protocol": "TCP"},
    {"Action": "Allow"},
    {"Direction": "Inbound"},
    {"Profile": "Domain, Private"},
])
def test_a_cut_rule_with_other_parameters_is_brought_to_the_catch_all_shape(changes):
    run = _standing_cut(**changes)
    done = rules_mod.cut(run)
    assert done["verified"] is True and done["problem"] is None
    view = run.rules["TDC-FW-ISO-cut"]
    assert (view["Direction"], view["Action"], view["Enabled"], view["Profile"]) == ("Outbound", "Block", True, "Any")
    assert (view["Program"], view["RemoteAddress"], view["RemotePort"], view["Protocol"]) == ("Any", ["Any"], ["Any"], "Any")
    assert rules_mod.cut_stands(run) is True


def test_the_repair_never_leaves_a_moment_without_the_rule():
    run = _standing_cut(Enabled=False, Program=IMAGE)
    rules_mod.cut(run)
    assert run.rules.removed == []
    assert all(any(n == "TDC-FW-ISO-cut" for n, _, _ in snapshot) for snapshot in run.standing)


def test_the_cut_branch_of_the_script_repairs_in_place_and_never_removes():
    text = open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()
    branch = text[text.index("'Cut' {"):]
    branch = branch[:branch.index("\n        }\n")]
    assert "Set-NetFirewallRule @want" in branch and "Name = $cut" in branch
    assert "Remove-NetFirewallRule" not in branch and "Remove-IsolateRules" not in branch


def test_a_repair_that_does_not_take_still_says_verified_false_and_why():
    run = _standing_cut(Enabled=False)
    run.repair_fails = True
    done = rules_mod.cut(run)
    assert done["verified"] is False
    assert "disabled" in done["problem"] and "access is denied" in done["problem"]
    assert rules_mod.cut_stands(run) is False


def test_a_cut_rule_that_stands_is_not_touched_again():
    run = FakeRun()
    rules_mod.cut(run)
    before = dict(run.rules["TDC-FW-ISO-cut"])
    run.repair_fails = True                            # would show as a problem if a repair were attempted
    done = rules_mod.cut(run)
    assert done["verified"] is True and run.rules["TDC-FW-ISO-cut"] == before


# ---- the two stages: isolate cuts, converge tidies up --------------------------------------------


def test_isolating_cuts_first_and_answers_after_the_cut():
    run, settings = make(foreign=STOCK)
    done = rules_mod.isolate(run, True, settings=settings)
    assert (done["stage"], done["verified"], done["converging"]) == ("cut", True, True)
    # the profiles are read for the way back, then the one Cut; Windows' 135 rules are not touched or read before the answer
    assert run.ops() == ["Profiles", "Cut"]
    assert settings.isolated is True and settings.stage == "cut"


def test_the_baseline_is_recorded_before_the_rule_is_written():
    run, settings = make(foreign=STOCK, outbound="NotConfigured")
    rules_mod.isolate(run, True, settings=settings)
    assert settings.outbound_before == "NotConfigured"
    saved = [i for i, (what, _) in enumerate(settings.timeline) if what == "settings"]
    cut = [i for i, (what, _) in enumerate(settings.timeline) if what == "Cut"]
    assert saved and cut and saved[0] < cut[0]


def test_nothing_is_cut_when_the_way_back_cannot_be_saved():
    run, settings = make(foreign=STOCK)
    settings.fail = True
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, settings=settings)
    assert run.rules == {} and "Cut" not in run.ops()


def test_converging_switches_the_allow_rules_off_and_drops_the_cut_rule():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "isolated" and done["verified"] is True
    assert rules_mod.CUT_RULE not in run.rules
    assert all(not r["Enabled"] for r in run.foreign.values())
    assert settings.stage == "isolated"
    assert set(run.outbound.values()) == {"Block"}


def test_the_cut_rule_falls_only_after_the_default_is_block_and_the_allow_rules_are_off():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    ops = run.ops()
    assert ops.index("DisableAllowOut") < ops.index("SetDefaultOutbound") < ops.index("Remove")


def test_a_rule_another_store_keeps_enabled_keeps_the_cut_rule_standing():
    run, settings = make(foreign={**STOCK, **GPO_RULE})
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut_policy"
    assert rules_mod.CUT_RULE in run.rules          # the only thing that closes it there
    assert done["allowed_out"] and "group policy" in done["note"]
    assert settings.stage == "cut_policy"


def test_converging_stops_at_the_next_call_when_it_is_cancelled():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: True)
    assert done["cancelled"] is True and done["stage"] == "cut"
    assert rules_mod.CUT_RULE in run.rules          # still closed
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]   # nothing switched off half-way
    assert "DisableAllowOut" not in run.ops()


def test_a_cancel_between_two_steps_stops_before_the_next_one():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    answers = iter([False, False, True])             # read, noted, the Windows rules go off; then it is cancelled
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: next(answers))
    assert done["cancelled"] is True and done["stage"] == "cut"
    assert "DisableAllowOut" in run.ops() and "SetDefaultOutbound" not in run.ops()
    assert rules_mod.CUT_RULE in run.rules
    assert settings.allow_disabled                  # the way back was noted before anything was switched off


def test_cutting_again_while_isolated_keeps_the_way_back():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    before, disabled = settings.outbound_before, list(settings.allow_disabled)
    assert before == "Allow" and disabled
    done = rules_mod.isolate(run, True, settings=settings)
    assert done["stage"] == "cut"
    assert settings.outbound_before == before and settings.allow_disabled == disabled
    assert settings.stage == "cut" and rules_mod.CUT_RULE in run.rules


def test_a_failed_converge_leaves_the_cut_standing_and_says_so():
    run, settings = make(foreign=STOCK, fail={"DisableAllowOut": (1, "denied")})
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and rules_mod.CUT_RULE in run.rules
    assert "denied" in done["note"] and done["verified"] is False
    assert settings.isolated is True and settings.allow_disabled   # not rolled back: the way back stays noted
    assert "EnableAllowOut" not in run.ops()


def test_a_failed_cut_of_a_fresh_isolation_leaves_nothing_behind():
    run, settings = make(foreign=STOCK, fail={"Cut": (1, "access is denied")})
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, settings=settings)
    assert settings.isolated is False and settings.outbound_before is None and settings.allow_disabled == []
    assert run.rules == {} and settings.stage == "open"


def test_a_profile_that_is_off_cuts_nothing():
    run, settings = make(foreign=STOCK, profiles={"Domain": True, "Private": True, "Public": False})
    with pytest.raises(rules_mod.ProfileOffError):
        rules_mod.isolate(run, True, settings=settings)
    assert run.rules == {} and settings.saved == [] and "Cut" not in run.ops()


def test_a_cancel_just_before_the_cut_rule_falls_leaves_it_standing():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    answers = iter([False, False, False, False, True])      # read, off, Block, the read back; then it is cancelled
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: next(answers))
    assert done["cancelled"] is True and done["stage"] == "cut" and rules_mod.CUT_RULE in run.rules
    assert set(run.outbound.values()) == {"Block"} and settings.stage == "cut"


def test_a_cut_rule_that_will_not_go_stays_and_the_stage_stays_cut():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    run.op_Remove = lambda p: (0, "", "")             # Remove says nothing and removes nothing
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "cut" and done["verified"] is False and "still there" in done["note"]
    assert rules_mod.CUT_RULE in run.rules and settings.stage == "cut"


def test_a_stage_that_cannot_be_saved_is_said_not_hidden():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    real = settings.set

    def set_(**changes):
        if "stage" in changes:
            raise OSError("disk full")
        return real(**changes)
    settings.set = set_
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert done["stage"] == "isolated" and "disk full" in done["note"] and rules_mod.CUT_RULE not in run.rules


def test_a_cut_that_is_not_read_back_as_the_catch_all_is_not_verified():
    run, settings = make(foreign=STOCK, disable_new=True)           # the rule is written, and it stands disabled
    done = rules_mod.isolate(run, True, settings=settings)
    assert done["stage"] == "cut" and done["verified"] is False and "disabled" in done["note"]


def test_leaving_after_a_failed_converge_switches_the_recorded_rules_back_on_and_drops_the_cut_rule():
    run, settings = make(foreign=STOCK, fail_once={"SetDefaultOutbound": (1, "denied")})
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: False)     # the rules are off, Block did not take
    assert done["stage"] == "cut" and run.enabled_foreign() == []
    left = rules_mod.isolate(run, False, settings=settings)
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE] and left["allow_disabled"] == []
    assert run.rules == {} and settings.isolated is False and set(run.outbound.values()) == {"Allow"}


def test_a_cancel_before_the_cut_rule_is_read_back_in_the_policy_stage_stops_there():
    run, settings = make(foreign={**STOCK, **GPO_RULE})
    rules_mod.isolate(run, True, settings=settings)
    answers = iter([False, False, False, False, True])     # read, off, Block, the read back; then the cut rule's own read
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: next(answers))
    assert done["cancelled"] is True and done["stage"] == "cut" and rules_mod.CUT_RULE in run.rules
    assert run.ops()[-1] == "AllowOut" and "Get" not in run.ops()          # no call after the cancel
    assert settings.stage == "cut"


def test_a_callback_that_raises_is_not_taken_for_a_failed_read():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    run.calls.clear()

    def broken():
        raise RuntimeError("callback bug")
    with pytest.raises(RuntimeError, match="callback bug"):
        rules_mod.converge(run, settings=settings, cancelled=broken)
    assert run.ops() == [] and run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]


def test_a_failed_fresh_cut_keeps_the_record_an_earlier_failed_leave_left():
    run, settings = make(foreign=STOCK, fail={"Cut": (1, "access is denied")})
    settings.allow_disabled = [DNS_RULE]                  # a rule an earlier leave could not switch on again
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, settings=settings)
    assert settings.isolated is False and settings.allow_disabled == [DNS_RULE] and settings.stage == "open"


def test_converging_again_after_a_failed_converge_finishes_the_job_and_records_nothing_twice():
    run, settings = make(foreign=STOCK, fail_once={"SetDefaultOutbound": (1, "denied")})
    rules_mod.isolate(run, True, settings=settings)
    first = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert first["stage"] == "cut" and sorted(settings.allow_disabled) == ["CoreNet-DHCP-Out", DNS_RULE]
    second = rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert second["stage"] == "isolated" and second["verified"] is True and rules_mod.CUT_RULE not in run.rules
    assert sorted(settings.allow_disabled) == ["CoreNet-DHCP-Out", DNS_RULE] and set(run.outbound.values()) == {"Block"}
    assert settings.stage == "isolated"


# ---- leaving: from any stage, and the cut rule goes with it ----------------------------------


def test_leaving_from_the_cut_stage_removes_the_rule_and_restores_the_baseline():
    run, settings = make(foreign=STOCK, outbound="NotConfigured")
    rules_mod.isolate(run, True, settings=settings)
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is True and rules_mod.CUT_RULE not in run.rules
    assert done["outbound_after"] == {n: "NotConfigured" for n in rules_mod.PROFILE_NAMES}
    assert run.outbound == {n: "NotConfigured" for n in rules_mod.PROFILE_NAMES}
    assert settings.stage == "open" and settings.isolated is False


def test_leaving_half_way_through_a_converge_switches_every_recorded_rule_on_again():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=_after_calls(run, 1))
    assert settings.allow_disabled                      # the record was made before anything was switched off
    rules_mod.isolate(run, False, settings=settings)
    assert all(r["Enabled"] for n, r in run.foreign.items() if n != "CoreNet-Teredo-Out")
    assert settings.allow_disabled == [] and rules_mod.CUT_RULE not in run.rules


def test_leaving_after_the_rules_were_switched_off_but_before_block_puts_them_back():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    stopped = rules_mod.converge(run, settings=settings, cancelled=_after_calls(run, 2))
    assert stopped["cancelled"] is True and run.enabled_foreign() == []        # they were off when it stopped
    done = rules_mod.isolate(run, False, settings=settings)
    assert run.enabled_foreign() == ["CoreNet-DHCP-Out", DNS_RULE]
    assert done["cut_removed"] is True and rules_mod.CUT_RULE not in run.rules and settings.stage == "open"
    assert settings.allow_disabled == [] and set(run.outbound.values()) == {"Allow"}


def test_leaving_from_cut_policy_removes_the_rule_too():
    run, settings = make(foreign=POLICY_STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.converge(run, settings=settings, cancelled=lambda: False)
    assert settings.stage == "cut_policy" and rules_mod.CUT_RULE in run.rules
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is True and rules_mod.CUT_RULE not in run.rules and settings.stage == "open"


def test_leaving_from_the_isolated_stage_has_no_cut_rule_to_remove():
    run, settings = make(foreign=STOCK)
    thorough(run, settings)
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is False and settings.stage == "open" and settings.isolated is False


def test_the_stage_and_the_marker_are_forgotten_in_one_write():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    rules_mod.isolate(run, False, settings=settings)
    assert settings.saved[-1]["stage"] == "open" and settings.saved[-1]["isolated"] is False
    assert [s for s in settings.saved if "stage" in s and s["stage"] == "open"] == [settings.saved[-1]]


def test_a_cut_rule_that_stays_after_leaving_is_raised_and_the_stage_stays_with_the_marker():
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    run.stuck_rules = {rules_mod.CUT_RULE}
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, False, settings=settings)
    assert settings.isolated is True and settings.stage == "cut"


def test_leaving_without_a_marker_still_takes_a_stray_cut_rule_away():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)                                  # no marker: a crash left it
    done = rules_mod.isolate(run, False, settings=settings)
    assert rules_mod.CUT_RULE not in run.rules and done["cut_removed"] is True
    assert done["changed"] is True and rules_mod.CUT_RULE in done["note"] and "removed" in done["note"]


def test_leaving_without_a_marker_and_without_a_cut_rule_removes_nothing():
    run, settings = make(foreign=STOCK)
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is False and done["changed"] is False and done["note"] is None


def test_a_stray_cut_rule_that_cannot_be_removed_is_said_not_raised():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    run.stuck_rules = {rules_mod.CUT_RULE}
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is False and rules_mod.CUT_RULE in run.rules
    assert rules_mod.CUT_RULE in done["note"] and "tdc-unisolate" in done["note"]


def test_leaving_without_a_marker_sweeps_when_the_cut_rule_cannot_be_looked_up():
    run, settings = make(foreign=STOCK)
    rules_mod.cut(run)
    run.fail = {"Get": (1, "rpc failed")}
    done = rules_mod.isolate(run, False, settings=settings)
    assert rules_mod.CUT_RULE not in run.rules and done["cut_removed"] is True


def test_the_note_after_a_stray_cut_rule_was_removed_does_not_say_nothing_was_changed():
    run, settings = make(foreign=STOCK, outbound="Block")        # the default is Block as well: the egress stays shut
    rules_mod.cut(run)
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is True and rules_mod.CUT_RULE not in run.rules
    assert "was removed" in done["note"] and "still blocked" in done["note"] and "tdc-unisolate" in done["note"]
    assert "nothing was changed" not in done["note"]


def test_the_note_without_a_marker_says_nothing_was_changed_only_when_nothing_was():
    unisolate = "tdc-unisolate"
    # nothing at all was done, the egress is shut anyway: the old sentence is true
    run, settings = make(foreign=STOCK, outbound="Block")
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["changed"] is False and "nothing was changed" in done["note"] and done["note"].count(unisolate) == 1
    # a leftover rule was switched on again: something was changed, and it is not denied
    run, settings = make(foreign=STOCK, outbound="Block")
    run.foreign[DNS_RULE]["Enabled"] = False
    settings.allow_disabled = [DNS_RULE]
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["changed"] is True and run.foreign[DNS_RULE]["Enabled"] is True
    assert "nothing was changed" not in done["note"] and "still blocked" in done["note"] and done["note"].count(unisolate) == 1
    # partly stuck: no "nothing was changed" next to "could not be switched on again"
    run, settings = make(foreign=STOCK, outbound="Block", stubborn={DNS_RULE})
    run.foreign[DNS_RULE]["Enabled"] = False
    run.foreign["CoreNet-DHCP-Out"]["Enabled"] = False
    settings.allow_disabled = [DNS_RULE, "CoreNet-DHCP-Out"]
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["changed"] is True and done["allow_disabled"] == [DNS_RULE]
    assert "nothing was changed" not in done["note"] and "could not be switched on again" in done["note"]
    # all stuck: nothing changed, and the note says both things without contradiction
    run, settings = make(foreign=STOCK, outbound="Block", stubborn={DNS_RULE})
    run.foreign[DNS_RULE]["Enabled"] = False
    settings.allow_disabled = [DNS_RULE]
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["changed"] is False and "nothing was changed" in done["note"] and "could not be switched on again" in done["note"]


def test_the_hatch_is_named_once_when_the_cut_rule_cannot_be_removed_and_outbound_is_blocked():
    run, settings = make(foreign=STOCK, outbound="Block")
    rules_mod.cut(run)
    run.stuck_rules = {rules_mod.CUT_RULE}
    done = rules_mod.isolate(run, False, settings=settings)
    assert done["cut_removed"] is False and done["changed"] is False
    assert done["note"].count("tdc-unisolate") == 1 and "could not be removed" in done["note"]
    assert "nothing was changed" in done["note"]
