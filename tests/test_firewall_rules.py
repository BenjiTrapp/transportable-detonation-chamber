"""Enforcement of the FIREWALL tab (webui/firewall_rules.py).

Nothing here touches a firewall: ``FakeRun`` stands in for ``run_powershell``. It speaks the contract of
webui/firewall_rules.ps1 (the ``-Op`` verbs, exit code 3 for "a profile is off", 4 for "the rule is already
there"), so these tests prove the Python side, the order of what it does and what it refuses to claim. What the
script really does to Windows only a VM can show.

**The honesty boundary.** ``FakeRun`` does not model that a Block rule beats an Allow rule, nor that a rule does
anything to traffic at all: it stores rules and gives them back. So no test here can prove that a rule works - that
the cut shuts the egress, that a block stops a flow, that loopback stays open. That blindness let the original
"default deny" through. What proves the effect are the VM checks in
docs/superpowers/plans/2026-11-16-firewall-tab-handover.md; a green run here is never evidence for it.
"""

import base64
import json
import ntpath
import os
import re
import subprocess
import sys
import threading

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


def test_the_rule_list_says_whether_the_cut_rule_stands_in_the_catch_all_shape():
    """The poll's rule list is one of the reads ``verified`` rests on in the cut stages (app._fw_cut_stands)."""
    run = FakeRun()
    rules_mod.cut(run)
    other = rules_mod.block(run, image=IMAGE, ip="1.2.3.4", fetcher=PY)["rule_id"]
    listed = {r["rule_id"]: r for r in rules_mod.rules(run)}
    assert listed[rules_mod.CUT_RULE]["cuts"] is True and listed[other]["cuts"] is False
    for change in ({"Enabled": False}, {"Action": "Allow"}, {"RemoteAddress": ["1.2.3.4"]}, {"Profile": "Domain"}):
        run.rules[rules_mod.CUT_RULE] = run.view(rules_mod.CUT_RULE, **change)
        assert {r["rule_id"]: r for r in rules_mod.rules(run)}[rules_mod.CUT_RULE]["cuts"] is False, change


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


class _CountingLock:
    """Stands in for ``rules_mod._LOCK`` and counts how often it is taken."""

    def __init__(self):
        self.real, self.taken = threading.RLock(), 0

    def acquire(self, *args, **kwargs):
        self.taken += 1
        return self.real.acquire(*args, **kwargs)

    def release(self):
        self.real.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


def test_a_sweep_with_nothing_to_remove_takes_no_lock_at_all(monkeypatch):
    """The press waits for whoever holds the lock; a sweep that only reads and changes nothing must never be that."""
    lock = _CountingLock()
    monkeypatch.setattr(rules_mod, "_LOCK", lock)
    seen = []
    monkeypatch.setattr(rules_mod, "CALL_OBSERVER", seen.append)
    run, _ = make()
    rules_mod.block(run, image=IMAGE, ip="5.6.7.8", fetcher=PY)          # a rule that is not the sweep's
    lock.taken = 0
    assert rules_mod.forget_fetch_rules(run) == ([], [])
    assert lock.taken == 0 and [(r["op"], r["lock"]) for r in seen][-1:] == [("List", None)]


def test_a_sweep_reads_without_the_lock_and_removes_under_it(monkeypatch):
    seen = []
    monkeypatch.setattr(rules_mod, "CALL_OBSERVER", seen.append)
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    seen.clear()
    assert rules_mod.forget_fetch_rules(run) == ([name], [])
    assert [(r["op"], r["lock"]) for r in seen] == [("List", None), ("Remove", "forget_fetch_rules"),
                                                    ("Get", "forget_fetch_rules")]


def test_a_rule_gone_between_the_read_and_the_lock_is_read_back_as_gone_not_stuck():
    run = FakeRun()
    name = rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"]
    real = run.op_List

    def listing(p):
        answer = real(p)
        run.rules.pop(name)                                # a fetch's own close got there first
        return answer
    run.op_List = listing
    assert rules_mod.forget_fetch_rules(run) == ([name], [])       # Remove is quiet about it, the read-back says gone


def test_a_rule_that_appears_after_the_read_is_left_for_the_next_sweep():
    run = FakeRun()
    real = run.op_List
    late = []

    def listing(p):
        answer = real(p)
        if not late:
            late.append(rules_mod.allow_fetch(run, fetcher=PY, ip="1.2.3.4", port=8080)["name"])
        return answer
    run.op_List = listing
    assert rules_mod.forget_fetch_rules(run) == ([], []) and late[0] in run.rules
    assert rules_mod.forget_fetch_rules(run) == (late, []) and late[0] not in run.rules

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


def test_startup_waits_for_a_rule_run_that_holds_the_lock():
    """It writes the stage, can forget the marker and switch rules on: a press or a convergence must not interleave."""
    import threading
    run, settings = FakeRun(outbound="Allow"), FakeSettings(isolated=True, outbound_before="Allow")
    started, answers = threading.Event(), []

    def start_up():
        started.set()
        answers.append(rules_mod.startup_state(run, settings))
    with rules_mod._LOCK:                       # a convergence is running
        worker = threading.Thread(target=start_up)
        worker.start()
        assert started.wait(5)
        worker.join(0.2)
        assert worker.is_alive() and run.calls == [] and settings.isolated is True
    worker.join(5)
    assert answers and run.calls and settings.isolated is False          # it ran once the lock was free


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
    # the way out of a failed panic press is to cut again, not the hatch that opens the egress
    assert "press again" in str(e.value) and "tdc-unisolate" not in str(e.value)
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


def _many_local_rules(count=400):
    return {f"{{{i:08d}-aaaa-bbbb-cccc-dddddddddddd}} *weird, name": {"DisplayName": f"App {i}", "Source": "Local",
                                                                     "Enabled": True}
            for i in range(count)}


def test_a_cancel_is_seen_between_the_chunks_of_switching_the_allow_rules_off():
    run, settings = make(foreign=_many_local_rules())
    rules_mod.isolate(run, True, settings=settings)
    # a press or a leave raises the flag while the first chunk is under way
    done = rules_mod.converge(run, settings=settings, cancelled=lambda: run.ops().count("DisableAllowOut") >= 1)
    assert done["cancelled"] is True and done["stage"] == "cut" and rules_mod.CUT_RULE in run.rules
    assert run.ops().count("DisableAllowOut") == 1, "the rest of the chunks were waited out"
    assert "SetDefaultOutbound" not in run.ops()
    still_on = run.enabled_foreign()
    assert 0 < len(still_on) < 400                                    # half done, and that is said
    assert str(400 - len(still_on)) in done["note"] and str(len(still_on)) in done["note"]
    # the record names every one of them, the switched-off and the not-reached alike
    assert sorted(settings.allow_disabled) == sorted(run.foreign)
    left = rules_mod.isolate(run, False, settings=settings)
    assert left["allow_disabled"] == [] and len(run.enabled_foreign()) == 400 and settings.allow_disabled == []


def test_setting_the_allow_rules_reports_what_a_cancel_left_unreached():
    run, _ = make(foreign=_many_local_rules())
    done, failed, missing, unreached = rules_mod._set_allow_out(
        run, list(run.foreign), False, cancelled=lambda: run.ops().count("DisableAllowOut") >= 1)
    assert failed == [] and missing == [] and done and unreached
    assert sorted(done + unreached) == sorted(run.foreign)
    assert sorted(unreached) == run.enabled_foreign()


def test_without_a_cancel_every_chunk_is_switched():
    run, _ = make(foreign=_many_local_rules())
    done, _, _, unreached = rules_mod._set_allow_out(run, list(run.foreign), False)
    assert unreached == [] and len(done) == 400 and run.enabled_foreign() == []


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


def test_a_callback_that_raises_between_the_chunks_is_not_taken_for_a_failed_step():
    run, settings = make(foreign=_many_local_rules())
    rules_mod.isolate(run, True, settings=settings)

    def broken():
        if run.ops().count("DisableAllowOut") >= 1:
            raise RuntimeError("callback bug")
        return False
    with pytest.raises(RuntimeError, match="callback bug"):
        rules_mod.converge(run, settings=settings, cancelled=broken)


def test_a_failed_fresh_cut_keeps_the_record_an_earlier_failed_leave_left():
    run, settings = make(foreign=STOCK, fail={"Cut": (1, "access is denied")})
    settings.allow_disabled = [DNS_RULE]                  # a rule an earlier leave could not switch on again
    with pytest.raises(rules_mod.RuleError):
        rules_mod.isolate(run, True, settings=settings)
    assert settings.isolated is False and settings.allow_disabled == [DNS_RULE] and settings.stage == "open"


@pytest.mark.parametrize("failure", ["refused", "unreadable"])
def test_a_failed_press_while_isolated_does_not_claim_the_cut_was_not_written_and_says_press_again(failure):
    """``cut`` can raise after PowerShell wrote the rule (an answer it cannot read, a timeout), so whether it was
    written again is not known; and whoever's panic press just failed wants to cut, not to open the egress."""
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    real = run.op_Cut
    if failure == "refused":
        run.fail["Cut"] = (1, "access is denied")
    else:
        run.op_Cut = lambda p: (real(p)[0], "{not json", "")          # written, then an answer that cannot be read
    with pytest.raises(rules_mod.RuleError) as raised:
        rules_mod.isolate(run, True, settings=settings)
    text = str(raised.value)
    assert "not known" in text and "was not written again" not in text
    assert "press" in text.lower() and "CUT AGAIN" in text
    assert "open the egress" not in text and settings.isolated is True


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


# ---- every PowerShell call is attributable: its op, the wait for the lock, its run time -------


class _Ticks:
    """A clock for ``rules_mod._clock`` that moves one second per reading, so durations are known, not measured."""

    def __init__(self):
        self.now = 100.0

    def __call__(self):
        self.now += 1.0
        return self.now


def _observed(monkeypatch):
    seen = []
    monkeypatch.setattr(rules_mod, "_clock", _Ticks())
    monkeypatch.setattr(rules_mod, "CALL_OBSERVER", seen.append)
    return seen


def test_every_call_of_a_locked_run_is_reported_with_its_op_its_wait_and_its_run_time(monkeypatch):
    seen = _observed(monkeypatch)
    run, settings = make(foreign=STOCK)
    rules_mod.isolate(run, True, settings=settings)
    assert [r["op"] for r in seen] == ["Profiles", "Cut"]
    for record in seen:
        assert set(record) == {"op", "lock", "wait_ms", "run_ms", "rc", "thread"}
        assert record["lock"] == "isolate" and record["rc"] == 0 and isinstance(record["thread"], str)
        assert record["run_ms"] == 1000.0                     # one tick between the start and the end of the call
    # the wait is the outermost acquisition's, given to the first call of the run; the next one waited for nothing
    assert seen[0]["wait_ms"] == 1000.0 and seen[1]["wait_ms"] == 0.0


def test_a_read_that_takes_no_lock_says_so(monkeypatch):
    seen = _observed(monkeypatch)
    run, _ = make()
    rules_mod.rules(run)
    assert [(r["op"], r["lock"], r["wait_ms"]) for r in seen] == [("List", None, None)]


def test_the_wait_is_measured_where_the_lock_is_taken(monkeypatch):
    seen = []
    clock = [0.0]
    asked = threading.Event()

    def reading():
        asked.set()
        return clock[0]
    monkeypatch.setattr(rules_mod, "_clock", reading)
    monkeypatch.setattr(rules_mod, "CALL_OBSERVER", seen.append)
    run, settings = make(foreign=STOCK)
    worker = threading.Thread(target=lambda: rules_mod.isolate(run, True, settings=settings))
    with rules_mod._LOCK:                                     # someone else's run holds it
        worker.start()
        assert asked.wait(5)                                  # the press has read the clock and now waits
        clock[0] = 7.5                                        # seven and a half seconds pass while it waits
    worker.join(5)
    assert seen[0]["op"] == "Profiles" and seen[0]["wait_ms"] == 7500.0


def test_an_observer_that_fails_changes_nothing(monkeypatch):
    def broken(record):
        raise RuntimeError("observer bug")
    monkeypatch.setattr(rules_mod, "CALL_OBSERVER", broken)
    run, settings = make(foreign=STOCK)
    assert rules_mod.isolate(run, True, settings=settings)["verified"] is True


# ---- module-free reads: TDC's rules over COM; the profiles stay on the cmdlets ---------------------


def _ps1():
    return open(os.path.join(ROOT, "webui", "firewall_rules.ps1"), encoding="utf-8").read()


def _validate_set(script):
    return re.search(r"ValidateSet\(([^)]*)\)\]\s*\[string\]\$Op", script).group(1)


def _functions(script):
    return {m.group(1): script[m.start():script.index("\n}\n", m.start())]
            for m in re.finditer(r"^function ([\w-]+) \{", script, re.M)}


def _op_case(script, verb):
    case = script[script.index("\n        '%s' {" % verb):]
    return case[:case.index("\n        }\n")]


def _op_branch(script, verb):
    """The code one verb runs: its case of the switch, and every function of the script it calls, transitively."""
    functions = _functions(script)
    parts, seen, todo = [_op_case(script, verb)], set(), [_op_case(script, verb)]
    while todo:
        text = todo.pop()
        for name, body in functions.items():
            if name not in seen and re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(name), text):
                seen.add(name)
                parts.append(body)
                todo.append(body)
    return "\n".join(parts)


def _lines_mentioning(text, needle):
    return [line for line in text.splitlines() if needle in line]


def test_compare_is_accepted_but_the_module_never_emits_it():
    module = open(os.path.join(ROOT, "webui", "firewall_rules.py"), encoding="utf-8").read()
    assert "'Compare'" in _validate_set(_ps1())
    assert '"Compare"' not in module and "'Compare'" not in module


# ---- a fallback is not silent: the way that answered reaches the call log ------------------------


def _answering(rows):
    def run(args):
        return 0, json.dumps(rows), ""
    return run


def _rows(**way):
    return [{"Name": n, "Enabled": True, "DefaultOutboundAction": "Allow", "Configured": "NotConfigured", **way}
            for n in ("Domain", "Private", "Public")]


def test_a_fallback_and_its_reason_are_reported_with_the_call(monkeypatch):
    seen = _observed(monkeypatch)
    reason = "COM DefaultOutboundAction of Public is not a known number: '3'"
    states = rules_mod._profiles(_answering(_rows(Via="cmdlet", Fallback=reason)))
    assert [s["configured"] for s in states] == ["NotConfigured"] * 3          # the contract is unchanged
    assert seen[0]["op"] == "Profiles" and seen[0]["via"] == "cmdlet" and seen[0]["fallback"] == reason


def test_the_fast_way_is_reported_without_a_reason(monkeypatch):
    seen = _observed(monkeypatch)
    rules_mod._profiles(_answering(_rows(Via="fast")))
    assert seen[0]["via"] == "fast" and "fallback" not in seen[0]


def test_an_answer_without_a_way_adds_nothing_to_the_report(monkeypatch):
    seen = _observed(monkeypatch)
    rules_mod._profiles(_answering(_rows()))
    assert set(seen[0]) == {"op", "lock", "wait_ms", "run_ms", "rc", "thread"}


@pytest.mark.parametrize("via", ["weird", 3, None])
def test_a_way_that_is_not_one_of_the_two_is_not_reported(monkeypatch, via):
    seen = _observed(monkeypatch)
    rules_mod._profiles(_answering(_rows(Via=via, Fallback="x")))
    assert "via" not in seen[0] and "fallback" not in seen[0]


def test_lists_two_reasons_reach_the_call_log_whole_and_on_one_line(monkeypatch):
    """When both halves of List fall back, each reason may be as long as Get-ShortReason allows; the log keeps both,
    and nothing from the machine in either reason can break the call line."""
    script = _ps1()
    short = re.search(r"Substring\(0, (\d+)\)", _functions(script)["Get-ShortReason"]).group(1)
    listing = _op_case(script, "List")
    parts = tuple(m.group(1) if m else None for m in (re.search(r'"([^"$]*)\$\(\$profileStates\.Fallback\)"', listing),
                                                        re.search(r"-join '([^']*)'", listing),
                                                        re.search(r'"([^"$]*)\$\(\$read\.Fallback\)"', listing)))
    assert int(short) == rules_mod.MAX_FALLBACK_CHARS and parts == rules_mod.LIST_FALLBACK_PREFIXES, \
        "MAX_LIST_FALLBACK_CHARS is two reasons cut by Get-ShortReason plus List's two prefixes and its separator: " \
        "change MAX_FALLBACK_CHARS / LIST_FALLBACK_PREFIXES in firewall_rules.py to match the script"
    assert rules_mod.MAX_LIST_FALLBACK_CHARS == 2 * int(short) + sum(map(len, parts))
    seen = _observed(monkeypatch)
    # a lone CR, a group separator and two Unicode line breaks survive Get-ShortReason's split on CR LF / LF
    odd = "a\rb\x1cc\u2028d\x85e"
    joined = "profiles: " + odd + "p" * (200 - len(odd)) + "; rules: " + odd + "r" * (200 - len(odd))
    rules_mod.rules(_answering({"profiles": _rows(), "rules": [], "Via": "cmdlet", "Fallback": joined}))
    assert seen[0]["op"] == "List" and seen[0]["via"] == "cmdlet" and seen[0]["fallback"] == joined
    logged = repr(seen[0]["fallback"])                    # the call line quotes it with %r
    assert not any(c in logged for c in "\n\r\x1c\u2028\x85"), logged
    rules_mod.rules(_answering({"profiles": _rows(), "rules": [], "Via": "cmdlet", "Fallback": joined + "x" * 5000}))
    assert seen[1]["fallback"] == joined                  # still bounded: past both whole reasons it is cut


def test_a_long_reason_is_cut_and_a_failed_call_is_still_reported(monkeypatch):
    seen = _observed(monkeypatch)
    rules_mod._profiles(_answering(_rows(Via="cmdlet", Fallback="x" * 5000)))
    assert len(seen[0]["fallback"]) == 200
    with pytest.raises(rules_mod.RuleError):
        rules_mod._profiles(lambda args: (_ for _ in ()).throw(OSError("gone")))
    assert seen[1]["op"] == "Profiles" and seen[1]["rc"] is None and "via" not in seen[1]


# ---- TDC's own rules without the module: List and Get over COM --------------------------------

RULE_FIELDS = ("Name", "Enabled", "Action", "Direction", "Profile", "Program", "RemoteAddress", "RemotePort", "Protocol")
# The properties of a COM rule the fast way reads: Name of every rule, the other eight of TDC's rules only.
COM_RULE_READS = ("Name", "Enabled", "Action", "Direction", "Profiles", "ApplicationName", "RemoteAddresses",
                  "RemotePorts", "Protocol")


def test_list_keeps_every_field_the_python_side_reads():
    branch = _op_branch(_ps1(), "List")
    for field in RULE_FIELDS:
        assert f'"{field}"' in branch, f"List lost {field}"


def test_list_asks_com_only_for_tdc_rules():
    """538 rules stand on this VM; only TDC-FW-* are ever reported."""
    script = _ps1()
    branch = _op_branch(script, "List")
    fast = _functions(script)["Read-FastRuleViews"]
    # List's rules come through the COM reader (not only its profiles), and that reader keeps TDC-FW-* alone
    assert "Read-FastRuleViews" in branch and "Get-OurRuleViews" in _op_case(script, "List")
    assert "$policy = New-Object -ComObject HNetCfg.FwPolicy2" in fast and "foreach ($rule in $policy.Rules) {" in fast
    assert "} elseif (-not $name.StartsWith('TDC-FW-', [System.StringComparison]::OrdinalIgnoreCase)) {" in fast


def test_the_fast_rule_view_has_exactly_the_fields_of_the_cmdlet_view():
    functions = _functions(_ps1())
    fast = functions["Read-FastRuleViews"]
    assert re.findall(r'^\s*"(\w+)" = ', fast, re.M) == list(RULE_FIELDS)
    assert re.findall(r"^\s*(\w+) = ", functions["Get-RuleView"], re.M) == list(RULE_FIELDS)


def test_every_number_of_the_rule_fast_path_is_written_out():
    """COM direction 1 In, 2 Out; action 0 Block, 1 Allow; Profiles a bitmask of 1 Domain, 2 Private, 4 Public, each
    combination spelled as the cmdlets' Profile flags print it and all of them (NET_FW_PROFILE2_ALL) as Any; protocol
    6 TCP, 17 UDP, 256 Any. Nothing else, and nothing computed: 7, ICMP or a new value is a fallback."""
    fast = _functions(_ps1())["Read-FastRuleViews"]

    def mapping(var):
        return dict(re.findall(r"'(\d+)' = '([\w, ]+)'", re.search(r"\$%s = @\{([^}]*)\}" % var, fast).group(1)))
    assert mapping("ComDirection") == {"1": "Inbound", "2": "Outbound"}
    assert mapping("ComAction") == {"0": "Block", "1": "Allow"}
    assert mapping("ComProfiles") == {"1": "Domain", "2": "Private", "3": "Domain, Private", "4": "Public",
                                      "5": "Domain, Public", "6": "Private, Public", "2147483647": "Any"}
    assert mapping("ComProtocol") == {"6": "TCP", "17": "UDP", "256": "Any"}
    assert not re.search(r"-band|-bor|-bxor|-shl|-shr|\[enum\]|-as \[", fast, re.I)


def test_an_unknown_rule_number_or_spelling_falls_back_instead_of_guessing():
    functions = _functions(_ps1())
    fast = functions["Read-FastRuleViews"]
    for var in ("ComDirection", "ComAction", "ComProfiles", "ComProtocol"):
        assert re.search(r"if \(-not \$%s\.ContainsKey\(\$\w+\)\) \{ throw " % var, fast), var
    assert "if (-not ($enabled -is [bool])) { throw " in fast
    # a program, an address or a port in a spelling that is not known is not passed on as it is: these are the only
    # ways a token gets through, and everything else throws
    lines = [l.strip() for l in fast.splitlines()]
    for line in (
            "elseif ($app -is [string] -and $app) { $program = $app }",
            "else { throw \"COM ApplicationName of $name is neither null nor a path: '$app'\" }",
            "else { throw \"COM RemoteAddresses of $name has a spelling that is not known: '$token'\" }",
            "if ($token -match '^\\d{1,5}\\z') { $token }",
            "else { throw \"COM RemotePorts of $name has a spelling that is not known: '$token'\" }",
            "else { throw \"COM RemotePorts of $name is not text: '$remotePorts'\" }"):
        assert line in lines, line
    assert len([l for l in lines if re.search(r"\{ \$token \}|\$Matches", l)]) == 1      # the port; addresses go by $single
    # an address is one token, or a range whose two ends are the same text, and that one address must be a host of
    # either family; these are all the lines that name $single, so no other way through exists
    assert [l for l in lines if re.search(r"\$single\b", l, re.I)] == [
        "if ($ends.Count -eq 1) { $single = $token }",
        "elseif ($ends.Count -eq 2 -and $ends[0] -ceq $ends[1]) { $single = $ends[0] }",
        "if ($single -match '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\z') { $single }",
        "elseif ($single -match '^[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\\z') { $single }",
    ]
    assert [l for l in lines if re.search(r"\$ends\b", l, re.I)] == [
        "$ends = $token.Split('-')",
        "if ($ends.Count -eq 1) { $single = $token }",
        "elseif ($ends.Count -eq 2 -and $ends[0] -ceq $ends[1]) { $single = $ends[0] }",
    ]
    assert lines.count("else { throw \"COM RemoteAddresses of $name has a spelling that is not known: '$token'\" }") == 2
    assert "if ($count -eq 0) { throw " in fast           # no rules at all is not "none of ours"
    assert re.search(r"if \(\$seen\.ContainsKey\(\$name\)\) \{ throw ", fast)      # two rules, one name
    way = functions["Get-OurRuleViews"]
    assert re.search(r"try \{\s*\$views = @\(Read-FastRuleViews -RuleName \$RuleName\)\s*"
                     r"return \[pscustomobject\]@\{ Views = \$views; Via = 'fast'; Fallback = \$null \}\s*"
                     r"\} catch \{\s*\$fallback = Get-ShortReason \$_\s*\}", way)
    assert "Via = 'cmdlet'; Fallback = $fallback" in way and "Read-CmdletRuleViews -RuleName $RuleName" in way


def test_only_tdc_rules_are_read_beyond_their_name():
    """The collection is enumerated, not queried: every rule costs its Name, and only ours the other eight reads."""
    fast = _functions(_ps1())["Read-FastRuleViews"]
    reads = re.findall(r"\$rule\.(\w+)", fast)
    assert sorted(reads) == sorted(COM_RULE_READS), reads          # each property read once, and nothing else
    loop = fast[fast.index("foreach ($rule in $policy.Rules) {"):]
    head, rest = loop.split("$seen[$name] = $true", 1)
    assert re.findall(r"\$rule\.(\w+)", head) == ["Name"]
    assert "continue" in head and "StartsWith('TDC-FW-'" in head
    assert "| Where-Object" not in loop and "| ForEach-Object" not in loop


def test_a_name_reaching_com_is_still_checked_and_matched_whole():
    """Get's -Name is Assert-OurName'd before any lookup, and the fast way compares it whole: no wildcard, no pattern."""
    script = _ps1()
    case = _op_case(script, "Get")
    assert case.index("Assert-OurName $Name") < case.index("Get-OurRuleViews -RuleName $Name")
    fast = _functions(script)["Read-FastRuleViews"]
    uses = [l.strip() for l in _lines_mentioning(fast, "$RuleName") if "param(" not in l]
    assert uses == ["if ($RuleName) {", "if ($name -ne $RuleName) { continue }"], uses


def test_the_cut_keeps_reading_its_rule_back_through_the_cmdlets():
    functions = _functions(_ps1())
    cut = _op_case(_ps1(), "Cut")
    assert "Get-RuleView $cut" in cut and "Get-OurRuleViews" not in cut and "Read-FastRuleViews" not in cut
    assert "FwPolicy2" not in functions["Get-RuleView"]


def test_compare_holds_every_rule_field_up_both_ways():
    script = _ps1()
    case = _op_case(script, "Compare")
    branch = _op_branch(script, "Compare")
    assert "Read-FastRuleViews" in case and "Read-CmdletRuleViews" in case
    assert "Get-NetFirewallRule -Name 'TDC-FW-*'" in branch and "Get-RuleView" in branch
    fields = re.search(r"foreach \(\$field in @\(('Name'[^)]*)\)\)", case).group(1)
    assert re.findall(r"'(\w+)'", fields) == list(RULE_FIELDS)
    # a rule only one way read is a difference, and the fast Get of one rule is held up as well as the fast List
    assert "'not found'" in case and "Read-FastRuleViews -RuleName" in case
    assert 'what = \'rules\'; fast = "error: $(Get-ShortReason $_)"' in case


# ---- the Name/DisplayName invariant, said and checked; and a Get that finds nothing still names its way ----


def test_the_com_reader_says_what_its_name_is_and_what_breaks_without_the_invariant():
    fast = _functions(_ps1())["Read-FastRuleViews"]
    said = fast[fast.index("$name = [string]$rule.Name"):fast.index("        if ($RuleName) {")]
    for word in ("DisplayName", "Create", "Cut", "DisplayName = Name", "Remove", "tdc-unisolate", "Compare"):
        assert word in said, word


def test_compare_checks_the_set_of_rule_names_on_its_own():
    """A rule only one side finds is its own, named difference, checked before and apart from the fields."""
    case = _op_case(_ps1(), "Compare")
    names = case.index('what = "$way rule names: $ruleName found by one side only"')
    fields = case.index("foreach ($field in @('Name'")
    assert names < fields and case.count("foreach ($way in $fastWays.Keys) {") == 2
    block = case[:fields][case[:fields].rindex("foreach ($way in $fastWays.Keys) {"):]
    assert "$differences +=" not in block                  # the field loop says nothing about the name set
    check = case[case.index("foreach ($way in $fastWays.Keys) {"):fields]
    assert "if ($inFast -ne $inCmdlet) {" in check and "'found'" in check and "'not found'" in check
    assert "# The set of names" in case


def test_a_get_that_finds_nothing_names_its_way_on_stderr_and_keeps_stdout_empty():
    case = _op_case(_ps1(), "Get")
    found, missing = case.split("} else {", 1)
    assert "ConvertTo-Json" in found and "[Console]::Error" not in found
    assert "[Console]::Out" not in missing and "Write-Output" not in missing
    assert "[Console]::Error.WriteLine((ConvertTo-Json -Compress -InputObject ([pscustomobject]$marker)))" in missing
    assert "Via = $read.Via" in missing and "$marker.Fallback = $read.Fallback" in missing


def _answering_err(out, err):
    def run(args):
        return 0, out, err
    return run


def test_a_missing_rule_reports_its_way_from_stderr(monkeypatch):
    seen = _observed(monkeypatch)
    reason = "COM gives no rules at all"
    assert rules_mod._describe(_answering_err("", '{"Via":"cmdlet","Fallback":"%s"}\r\n' % reason), "TDC-FW-ISO-cut") is None
    assert seen[0]["op"] == "Get" and seen[0]["via"] == "cmdlet" and seen[0]["fallback"] == reason
    assert rules_mod._describe(_answering_err("", '{"Via":"fast"}\n'), "TDC-FW-ISO-cut") is None
    assert seen[1]["via"] == "fast" and "fallback" not in seen[1]


def test_the_way_on_stdout_wins_and_other_stderr_adds_nothing(monkeypatch):
    seen = _observed(monkeypatch)
    rules_mod._profiles(_answering_err(json.dumps(_rows(Via="fast")), '{"Via":"cmdlet","Fallback":"x"}'))
    assert seen[0]["via"] == "fast" and "fallback" not in seen[0]
    for err in ("WARNING: something\n{not json", '{"Via": broken', '{"Via":"weird"}', "", None, '["Via"]'):
        rules_mod._describe(_answering_err("", err), "TDC-FW-ISO-cut")
        assert set(seen[-1]) == {"op", "lock", "wait_ms", "run_ms", "rc", "thread"}, err


# ---- the code lines of a text, comments left out ------------------------------------------------


def _code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ---- the invariant itself, not the name set as its proxy ----------------------------------------


def test_compare_checks_that_each_tdc_rule_has_its_name_as_its_display_name():
    case = _op_case(_ps1(), "Compare")
    lines = _code_lines(case)
    assert "foreach ($rule in @(Get-NetFirewallRule -Name 'TDC-FW-*' -ErrorAction SilentlyContinue)) {" in lines
    assert "if (-not ([string]$rule.DisplayName -ceq [string]$rule.Name)) {" in lines
    assert 'what = "rule $([string]$rule.Name) DisplayName is not its Name"' in lines
    assert "fast = [string]$rule.DisplayName" in lines and "cmdlet = [string]$rule.Name" in lines


# ---- the stderr marker: Get alone, and split where PowerShell breaks a line -----------------------


def test_a_marker_whose_reason_holds_unicode_line_separators_is_still_read(monkeypatch):
    seen = _observed(monkeypatch)
    reason = "sample said \u2028 and \x85 and \u001c"
    err = json.dumps({"Via": "cmdlet", "Fallback": reason}, ensure_ascii=False) + "\r\n"
    assert "\u2028" in err and "\x85" in err
    rules_mod._describe(_answering_err("", err), "TDC-FW-ISO-cut")
    assert seen[0]["via"] == "cmdlet" and seen[0]["fallback"] == reason


def test_only_get_takes_its_way_from_stderr(monkeypatch):
    seen = _observed(monkeypatch)
    marker = '{"Via":"cmdlet","Fallback":"x"}\n'
    rules_mod._ok(_answering_err("", marker), "Remove", Name="TDC-FW-ISO-cut")
    rules_mod._ok(_answering_err("", marker), "Enable")
    assert [set(r) for r in seen] == [{"op", "lock", "wait_ms", "run_ms", "rc", "thread"}] * 2
    rules_mod._ok(_answering_err("", marker), "Get", Name="TDC-FW-ISO-cut")
    assert seen[-1]["via"] == "cmdlet"



# ---- AllowOut stays on the cmdlets: CIM could read the ActiveStore now, and the gain does not pay for the risk ------


def test_allowout_stays_on_the_cmdlets_because_the_gain_does_not_pay_for_the_risk():
    """The old name said CIM cannot read the ActiveStore. Measured on 2026-11-19 that is false: the PolicyStore
    operation option reads it and finds the same 136 enabled outbound Allow rules as the cmdlet, the policy rule with
    PolicyStoreSourceType 2. AllowOut stays on the cmdlets because it would save 0.4 s on a call that never appears in
    the steady load, and it is the verb where a mistake reports closed while traffic still goes out. So it reads
    Get-NetFirewallRule -PolicyStore ActiveStore and its profiles through the cmdlets alone, and nothing of it goes over
    COM or the option."""
    script = _ps1()
    case = _code_lines(_op_case(script, "AllowOut"))
    assert case == [
        "'AllowOut' {",
        "ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ profiles = (Get-ProfileStates -CmdletsOnly).Rows; "
        "rules = @(Get-ForeignAllowOut) })",
    ], case
    cmdlet = _code_lines(_functions(script)["Get-ForeignAllowOut"])
    assert "@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {" in cmdlet
    assert not re.search(r"CimInstance|CimSession|EnumerateInstances|SetCustomOption|FwPolicy2|ComObject",
                         "\n".join(cmdlet), re.I)
    # no rule of the firewall is read over CIM anywhere in the script, and Compare has nothing of AllowOut to compare
    assert not re.search(r"MSFT_NetFirewallRule", "\n".join(_code_lines(script)), re.I)
    assert "Get-ForeignAllowOut" not in _op_case(script, "Compare")
    # its profiles cannot reach the fast reader: -CmdletsOnly skips it (pinned with Compare's cmdlet side below)
    assert "Read-FastProfileStates" not in _op_case(script, "AllowOut")


def test_the_cmdlet_way_of_allow_out_is_what_it_was():
    cmdlet = _functions(_ps1())["Get-ForeignAllowOut"]
    lines = _code_lines(cmdlet)
    assert re.findall(r"^\s*(\w+) = \[string\]", cmdlet, re.M) == ["Name", "DisplayName", "Group", "Source"]
    assert "Source = [string]$_.PolicyStoreSourceType" in lines and "Group = [string]$_.DisplayGroup" in lines
    assert "-not ([string]$_.Name).StartsWith('TDC-FW-')" in lines


def test_the_switching_verbs_look_their_rules_up_in_the_persistentstore_themselves():
    """DisableAllowOut and EnableAllowOut act only on the named local outbound Allow rules they find themselves."""
    body = _functions(_ps1())["Set-AllowOut"]
    assert ("$found = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {" in body and
            "$want.ContainsKey([string]$_.Name) -and [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow'" in body)
    assert "Get-ForeignAllowOut" not in body


def test_only_a_rule_whose_source_is_local_counts_as_one_isolated_can_switch_off():
    answer = {"profiles": _rows(),
              "rules": [{"Name": "Pol-Out", "DisplayName": "Policy", "Group": "", "Source": "GroupPolicy"},
                        {"Name": "Num-Out", "DisplayName": "Number", "Group": "", "Source": "2"},
                        {"Name": "Loc-Out", "DisplayName": "Local one", "Group": "G", "Source": "Local"}]}
    found = rules_mod.allowed_out(_answering(answer))
    assert [(r["name"], r["local"]) for r in found] == [("Loc-Out", True), ("Num-Out", False), ("Pol-Out", False)]


def test_compare_counts_each_kind_of_rule_check_on_its_own_and_writes_nothing():
    """An ok over no rule at all must not read like an ok over fifty fields: how many rules either way found, and
    each kind of check (the profiles' fields, display names, the name sets, the rules' fields), are said apart."""
    script = _ps1()
    case = _op_case(script, "Compare")
    lines = _code_lines(case)
    assert "$checked = [ordered]@{ profiles = 0; displayNames = 0; names = 0; fields = 0 }" in lines
    assert [l for l in lines if "+= 1" in l] == ["$checked.profiles += 1", "$checked.displayNames += 1",
                                                 "$checked.names += 1", "$checked.fields += 1"]
    assert "ok = $ok; rules = $ruleNames.Count; checked = [pscustomobject]$checked; differences = $differences" in lines
    assert "exit 1" in case
    assert not re.search(r"\b(Set|New|Remove|Enable|Disable)-NetFirewall", _op_branch(script, "Compare"))


def test_list_says_the_way_both_its_halves_were_read_and_get_the_way_of_its_rule():
    """List has two fast halves, its profiles and its rules: Via is fast only when both were, and Fallback names every
    half that fell back with its own reason (each already one short line from Get-ShortReason), joined by "; "."""
    script = _ps1()
    listing = _code_lines(_op_case(script, "List"))
    assert listing == [
        "'List' {",
        "$profileStates = Get-ProfileStates",
        "$read = Get-OurRuleViews",
        "$fallbacks = @()",
        "if ($profileStates.Via -ne 'fast') { $fallbacks += \"profiles: $($profileStates.Fallback)\" }",
        "if ($read.Via -ne 'fast') { $fallbacks += \"rules: $($read.Fallback)\" }",
        "$out = [ordered]@{ profiles = $profileStates.Rows; rules = $read.Views; Via = 'fast' }",
        "if ($fallbacks.Count -gt 0) { $out.Via = 'cmdlet'; $out.Fallback = $fallbacks -join '; ' }",
        "ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]$out)",
    ], listing
    get = _code_lines(_op_case(script, "Get"))
    for line in ("$read = Get-OurRuleViews -RuleName $Name",
                 "$view | Add-Member -NotePropertyName Via -NotePropertyValue $read.Via",
                 "if ($read.Via -ne 'fast') { $view | Add-Member -NotePropertyName Fallback -NotePropertyValue $read.Fallback }"):
        assert line in get, line


def _script_parameters(script):
    block = re.search(r"^param\((.*?)^\)", script, re.S | re.M)
    return re.findall(r"\$(\w+)\s*(?=[,=\n])", block.group(1) + "\n"), script[:block.end()].count("\n") + 1


def _script_level_lines(script):
    """(line number, code) of every line after the param() block that is not inside a function: the code that runs in
    the script's own scope, the scope its parameters live in. Comment lines are left out."""
    _, last = _script_parameters(script)
    lines, inside, found = [], False, 0
    for number, line in enumerate(script.splitlines(), 1):
        if number <= last:
            continue
        if re.match(r"function [\w-]+ \{", line):
            assert not inside, ("_script_level_lines: line %d starts a function before the one above it was closed by a "
                                "`}` at column 0; the line numbers it would give are wrong" % number)
            inside, found = True, found + 1
        elif inside and line == "}":
            inside = False
        elif not inside and line.strip() and not line.strip().startswith("#"):
            lines.append((number, line.strip()))
    declared = len(re.findall(r"^function ", script, re.M))
    assert found == declared and not inside, (
        "_script_level_lines read %d functions of the form `function Name {` ... `}` at column 0, but the script "
        "declares %d (and %s): a function written another way (its brace on the next line, or a `}` at column 0 "
        "inside it, such as in a here-string) is mis-parsed, and the line numbers it gives are wrong. Fix the parser "
        "before trusting it." % (found, declared, "one is never closed" if inside else "every one it read is closed"))
    return lines


_WRITES = (re.compile(r"(?<![\w$`])\$(?:(?:script|local|global|private):)?(\w+)\s*(?:[-+*/%]?=(?!=)|\+\+|--)", re.I),
           re.compile(r"\bforeach\s*\(\s*\$(\w+)\s+in\b", re.I),
           re.compile(r"-(?:Out|Error|Warning|Information|Pipeline)Variable\s+['\"]?\+?(\w+)", re.I),
           re.compile(r"\b(?:Set|New)-Variable\s+(?:-Name\s+)?['\"]?(\w+)", re.I))


def _variables_written(line):
    names = [n for pattern in _WRITES for n in pattern.findall(line)]
    multi = re.match(r"((?:\$\w+\s*,\s*)+\$\w+)\s*=(?!=)", line)
    return names + (re.findall(r"\$(\w+)", multi.group(1)) if multi else [])


def test_no_script_level_assignment_writes_into_a_parameter():
    """Shipped once: List did `$profiles = Get-ProfileStates`, and every List answered profiles null, Via cmdlet and
    an empty reason. PowerShell variable names are case-insensitive, and the switch runs in the script's own scope,
    where the parameters live: so $profiles IS the [string]$Profiles parameter, the assignment rebinds it, [string]
    coerces the read to its ToString(), and .Rows, .Via and .Fallback are then $null. Inside a function the same name
    is a fresh local, so functions are exempt. The parameters and the script-level code are both read out of the
    script, so a parameter added tomorrow is guarded too. (No other test could see this: the others read the script
    as text and the module's tests answer from canned JSON, so none of them ever runs PowerShell.)"""
    script = _ps1()
    params, _ = _script_parameters(script)
    lines = _script_level_lines(script)
    assert "Op" in params and len(params) > 1, params
    assert "switch ($Op) {" in [code for _, code in lines], "the switch must be among the script-level lines"
    written = {name.lower() for _, code in lines for name in _variables_written(code)}
    assert {"read", "fallbacks", "out"} <= written, written      # the scanner sees the switch's own assignments
    collisions = ["line %d: writes into the parameter $%s   ->   %s" % (number, param, code)
                  for number, code in lines for name in _variables_written(code)
                  for param in params if name.lower() == param.lower()]
    assert not collisions, (
        "\n".join(collisions) + "\nAn assignment at script level (the switch and the code around it, outside any "
        "function) to a parameter's name, in any case, is not a new local: PowerShell names are case-insensitive and "
        "this is the parameters' scope, so it rebinds the typed parameter and [string] turns the value into its "
        "ToString(). Pick a name no parameter has.")


def test_a_reason_is_one_short_line_in_the_rule_reads_and_in_compare_alike():
    script = _ps1()
    reason = _functions(script)["Get-ShortReason"]
    assert '-split "`r?`n"' in reason and "Substring(0, 200)" in reason
    assert "$fallback = Get-ShortReason $_" in _functions(script)["Get-OurRuleViews"]
    assert 'fast = "error: $(Get-ShortReason $_)"' in _op_case(script, "Compare")
    assert "$_.Exception.Message" not in _op_case(script, "Compare")


# ---- Profiles in force without the module: CIM with the PolicyStore option, proved per call by a sentinel ---------


def _function_body(script, name):
    """The body of one function of the script: the lines between `function <name> {` and its closing brace."""
    head = re.search(r"^function %s \{\n" % re.escape(name), script, re.M)
    assert head, "the script has no function %s" % name
    return script[head.end():script.index("\n}\n", head.end())]


def test_profiles_reads_cim_with_the_option_and_never_com():
    """COM reads the local store, which is why the previous attempt was
    reverted; the profile read must not go back to it."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assert "SetCustomOption" in fast and "MSFT_NetFirewallProfile" in fast
    assert "FwPolicy2" not in fast, "the profiles must not be read over COM"
    assert "Create('.')" in fast, "Create($null) fails with 'Der Parameter ist ungueltig'"
    # Kept from the pin this replaces, and still the reason it was written: measured on the VM, local GPO Domain
    # outbound Allow, PersistentStore Block, ActiveStore (in force) Allow, COM 0 = Block. COM reads the local store, so
    # where a policy sets Allow over the local Block that ISOLATED writes, a COM read says closed while the egress is
    # open. No way to the profiles, fast or cmdlet, in any verb, goes over COM.
    script = _ps1()
    com = r"FwPolicy2|ComObject|FirewallEnabled|DefaultOutboundAction\("
    assert not re.search(com, "\n".join(_code_lines(_op_branch(script, "Profiles"))), re.I)
    for name in ("Get-ProfileStates", "Read-FastProfileStates"):
        assert not re.search(com, _function_body(script, name), re.I), name
    for verb in ("Profiles", "List", "Create", "Cut", "SetDefaultOutbound", "AllowOut", "Compare"):
        assert "Get-ProfileStates" in _op_case(script, verb), verb
        assert not re.search(r"FirewallEnabled|DefaultOutboundAction\(", _op_case(script, verb), re.I), verb
    assert not re.search(r"FirewallEnabled|DefaultOutboundAction\(", "\n".join(_code_lines(script)), re.I)


def test_the_profile_maps_are_exactly_what_was_measured():
    """DefaultOutboundAction 0 NotConfigured, 2 Allow, 4 Block, and the three names as themselves (both forms were
    seen from the same class on the same VM); Enabled 0 false, 1 true. Nothing else, nothing computed."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    outbound = re.search(r"\$CimOutbound = @\{([^}]*)\}", fast).group(1)
    assert dict(re.findall(r"'(\w+)' = '(\w+)'", outbound)) == {
        "0": "NotConfigured", "2": "Allow", "4": "Block",
        "NotConfigured": "NotConfigured", "Allow": "Allow", "Block": "Block"}
    assert len(re.findall(r"=", outbound)) == 6, outbound
    enabled = re.search(r"\$CimEnabled = @\{([^}]*)\}", fast).group(1)
    assert dict(re.findall(r"'(\w+)' = (\$\w+)", enabled)) == {"0": "$false", "1": "$true"}
    assert len(re.findall(r"=", enabled)) == 2, enabled
    assert not re.search(r"-band|-bor|-bxor|-shl|-shr|\[enum\]|-as \[|\[bool\]", fast, re.I)


def test_a_profile_value_is_matched_case_exactly_or_refused():
    """A PowerShell hashtable ignores case, so ContainsKey alone would let `block` through unlisted."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    checks = [l.strip() for l in fast.splitlines() if "ContainsKey($Value)" in l]
    assert len(checks) == 1 and checks[0].startswith(
        "if (-not ($Map.ContainsKey($Value) -and @($Map.Keys) -ccontains $Value)) { throw "), checks
    assert "$Value" in checks[0][checks[0].index("throw "):], "the throw names the value it refused"
    # every profile value goes through that one check
    for line in _code_lines(fast):
        if re.search(r"\$Cim(Outbound|Enabled)\b", line) and "= @{" not in line:
            assert "& $mapped $Cim" in line, line
    # a profile name is matched exactly, and every profile must be there once
    assert "if (-not ($AllProfiles -ccontains $name)) { throw " in fast
    assert re.search(r"if \(\$rows\.ContainsKey\(\$name\)\) \{ throw ", fast)
    assert re.search(r"if \(-not \$rows\.ContainsKey\(\$name\)\) \{ throw ", fast)


def test_no_store_is_read_before_the_sentinel_and_each_table_holds_its_own_store():
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    lines = _code_lines(fast)
    reads = [(i, l) for i, l in enumerate(lines) if re.search(r"& \$(optionsOf|readStore) '", l)]
    assert [re.search(r"& \$(?:optionsOf|readStore) '([^']+)'", l).group(1) for _, l in reads] == [
        "TDC|NoSuchStore", "ActiveStore", "PersistentStore"], reads
    sentinel = reads[0][0]
    assert "foreach ($p in @(& $enumerate (& $optionsOf $Store))) {" in lines
    assert all(sentinel < i for i, l in enumerate(lines) if re.search(r"ActiveStore|PersistentStore", l)), \
        "no store may be named before the sentinel is read"
    in_force = [l for l in lines if re.search(r"\$inForce\s*\[.*\]\s*=", l, re.I)]
    configured = [l for l in lines if re.search(r"\$configured\s*\[.*\]\s*=", l, re.I)]
    assert len(in_force) == 1 and "& $readStore 'ActiveStore'" in in_force[0], in_force
    assert len(configured) == 1 and "& $readStore 'PersistentStore'" in configured[0], configured
    assert "PersistentStore" not in in_force[0] and "Enabled" not in configured[0]
    rows = [l for l in lines if re.search(r"^(Enabled|DefaultOutboundAction|Configured) = ", l)]
    assert rows == ["Enabled = $inForce[$name].Enabled", "DefaultOutboundAction = $inForce[$name].Outbound",
                    "Configured = $configured[$name]"], rows


def test_the_sentinels_verdict_is_three_consecutive_exact_lines():
    """The safety of the whole design sits in these lines, and a one-token edit to any of them would silently disable
    it: starting from a value that passes, a catch that counts any error, a condition that can never be true. The
    sentinel is read raw through $enumerate, so any answer, even an empty one, is an answer. Only a CimException with
    NativeErrorCode Failed, the refusal measured on the VM, counts as proof; anything else throws into the cmdlets."""
    lines = _code_lines(_function_body(_ps1(), "Read-FastProfileStates"))
    start = lines.index("$refused = $null")
    # the options are built before the counted try: only the enumeration may count as the provider's refusal
    assert re.fullmatch(r"\$sentinel = & \$optionsOf '[^']+'", lines[start - 1]), lines[start - 1]
    assert lines[start + 1] == "try { $null = & $enumerate $sentinel } catch { $refused = $_.Exception.GetBaseException() }"
    assert re.fullmatch(r'if \(-not \(\$refused -is \[Microsoft\.Management\.Infrastructure\.CimException\] -and '
                        r'\$refused\.NativeErrorCode -eq \[Microsoft\.Management\.Infrastructure\.NativeErrorCode\]::Failed\)\) '
                        r'\{ throw "[^\n]*sentinel[^\n]*" \}', lines[start + 2]), lines[start + 2]
    assert len([l for l in lines if re.search(r"\$refused\b", l)]) == 3, "$refused is used in those three lines only"
    assert len([l for l in lines if re.search(r"\$sentinel\b", l)]) == 2, "the sentinel's options serve its read only"


def test_the_cim_session_is_the_local_one_and_is_closed():
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    lines = _code_lines(fast)
    assert "$session = [Microsoft.Management.Infrastructure.CimSession]::Create('.')" in lines
    assert "$options.SetCustomOption('PolicyStore', $Store, $false)" in lines
    assert "@($session.EnumerateInstances('root/StandardCimv2', 'MSFT_NetFirewallProfile', $Options))" in lines
    assert "} finally {" in lines and "$session.Dispose()" in lines
    assert not re.search(r"Import-Module|Get-NetFirewall|Get-CimInstance|ComObject", fast, re.I)


def test_configured_is_touched_in_these_lines_of_the_script_and_nowhere_else():
    """Shipped twice: an in-force value restored as the configured one leaves the host configured differently from
    how it was found. Configured, the store ISOLATED remembers and puts back, is named in exactly these code lines of
    the whole script: each reader's own table, filled from the PersistentStore and put into its rows, and the name of
    the field Compare compares. A new Configured in any verb, or anything else filling the table, is a failure here."""
    script = _ps1()
    access = (r"\.configured\b", r"(?<![\w$])configured\s*=", r"['\"]configured['\"]",
              r"Add-Member\b.*(?<![\w$])configured\b", r"\$configured\b", r"-NotePropertyName\s+['\"]?configured")
    found = [l for l in _code_lines(script) if any(re.search(a, l, re.I) for a in access)]
    fast = ["$configured = @{}",
            "foreach ($p in @(& $readStore 'PersistentStore')) { $configured[$p.Name] = & $mapped $CimOutbound $p 'DefaultOutboundAction' }",
            "Configured = $configured[$name]"]
    cmdlet = ["$configured = @{}",
              "$configured[[string]$p.Name] = [string]$p.DefaultOutboundAction",
              "Configured = $configured[[string]$_.Name]"]
    compare = ["foreach ($field in @('Enabled', 'DefaultOutboundAction', 'Configured')) {"]
    assert found == fast + cmdlet + compare, found
    # and each sits where it belongs: the fast lines in the fast reader, the cmdlet lines behind the PersistentStore
    # cmdlet read of Get-ProfileStates, the field name in Compare
    fast_body = _code_lines(_function_body(script, "Read-FastProfileStates"))
    states = _code_lines(_function_body(script, "Get-ProfileStates"))
    assert all(l in fast_body for l in fast) and all(l in states for l in cmdlet)
    assert states.index(cmdlet[1]) == states.index("foreach ($p in @(Get-NetFirewallProfile -PolicyStore PersistentStore)) {") + 1
    assert compare[0] in _code_lines(_op_case(script, "Compare"))


def test_profiles_tries_the_fast_way_first_and_falls_back_to_the_cmdlets_unchanged():
    script = _ps1()
    states = _function_body(script, "Get-ProfileStates")
    assert re.search(r"if \(-not \$CmdletsOnly\) \{\s*try \{\s*\$rows = @\(Read-FastProfileStates\)\s*"
                     r"return \[pscustomobject\]@\{ Rows = \$rows; Via = 'fast'; Fallback = \$null \}\s*"
                     r"\} catch \{\s*\$fallback = Get-ShortReason \$_\s*\}\s*\}", states), states
    # the cmdlet read as it always was, now behind the fast one
    cmdlet = states[states.index("    $configured = @{}"):]
    assert cmdlet.index("Get-NetFirewallProfile -PolicyStore PersistentStore") < cmdlet.index(
        "Get-NetFirewallProfile -PolicyStore ActiveStore")
    assert "Configured = $configured[[string]$_.Name]" in cmdlet
    assert "return [pscustomobject]@{ Rows = $rows; Via = 'cmdlet'; Fallback = $fallback }" in _code_lines(cmdlet)


def test_the_profiles_rows_name_the_way_they_were_read():
    lines = _code_lines(_op_case(_ps1(), "Profiles"))
    assert lines == [
        "'Profiles' {",
        "$read = Get-ProfileStates",
        "foreach ($row in $read.Rows) {",
        "$row | Add-Member -NotePropertyName Via -NotePropertyValue $read.Via",
        "if ($read.Via -ne 'fast') { $row | Add-Member -NotePropertyName Fallback -NotePropertyValue $read.Fallback }",
        "}",
        "ConvertTo-Json -Compress -Depth 3 -InputObject $read.Rows",
    ], lines


def test_every_other_caller_takes_the_rows_and_the_writing_verbs_keep_the_cmdlets():
    """The verbs that write check and read back the profiles as they always did, through the cmdlets. And no caller
    puts the {Rows, Via, Fallback} wrapper itself into an answer, which would change the JSON's shape: a read used
    in place is used for its .Rows, a read held in a variable only for its .Rows, .Via and .Fallback, and every
    profiles of an answer is .Rows."""
    script = _ps1()
    for verb in ("List", "AllowOut", "Create", "Cut", "SetDefaultOutbound"):
        case = _op_case(script, verb)
        inline = re.findall(r"\(Get-ProfileStates[^)]*\)(\.Rows)?", case)
        held = re.findall(r"(\$\w+) = Get-ProfileStates\b", case)
        assert inline or held, verb
        assert all(inline), verb
        for var in held:
            uses = re.findall(r"%s(?!\w)(\.\w+)?" % re.escape(var), case)[1:]
            assert ".Rows" in uses and set(uses) <= {".Rows", ".Via", ".Fallback"}, (verb, var, uses)
        for value in re.findall(r"(?<![$\w])profiles = ([^;}]+)", case):
            assert value.strip().endswith(".Rows"), (verb, value)
    for verb in ("Create", "Cut", "SetDefaultOutbound", "AllowOut"):
        assert "(Get-ProfileStates -CmdletsOnly).Rows" in _op_case(script, verb), verb
    assert "$profileStates = Get-ProfileStates" in _code_lines(_op_case(script, "List"))
    for verb in ("Enable", "Remove", "DisableAllowOut", "EnableAllowOut", "RemoveIsolate"):
        assert "ProfileStates" not in _op_case(script, verb), verb


def test_compare_holds_each_profile_up_both_ways_read_on_their_own():
    script = _ps1()
    case = _op_case(script, "Compare")
    lines = _code_lines(case)
    assert "$checked = [ordered]@{ profiles = 0; displayNames = 0; names = 0; fields = 0 }" in lines
    assert "foreach ($row in @((Get-ProfileStates -CmdletsOnly).Rows)) { $cmdletProfiles[[string]$row.Name] = $row }" in lines
    assert "foreach ($row in @(Read-FastProfileStates)) { $fastProfiles[[string]$row.Name] = $row }" in lines
    assert "foreach ($field in @('Enabled', 'DefaultOutboundAction', 'Configured')) {" in lines
    assert "$checked.profiles += 1" in lines
    assert "if (-not (Test-SameValue $a $b)) {" in lines
    assert 'what = \'profiles\'; fast = "error: $(Get-ShortReason $_)"' in case
    # the profiles are compared before the rules, and a profile pass that fails stops at its own difference
    assert case.index("$checked.profiles += 1") < case.index("$cmdletRules = @{}")


def test_compares_cmdlet_side_can_never_be_the_fast_reader():
    """A comparison whose two sides can reach the same reader proves nothing. Compare's cmdlet side is
    Get-ProfileStates -CmdletsOnly, and with that switch the fast reader is not reached at all: it is called in the one
    block the switch skips, and nowhere after it."""
    script = _ps1()
    states = _function_body(script, "Get-ProfileStates")
    lines = _code_lines(states)
    assert lines[0] == "param([switch]$CmdletsOnly)"
    guard = lines.index("if (-not $CmdletsOnly) {")
    close = lines.index("}", lines.index("$fallback = Get-ShortReason $_"))
    calls = [i for i, l in enumerate(lines) if "Read-FastProfileStates" in l]
    assert calls and all(guard < i < close for i in calls), (guard, close, calls)
    assert lines[close + 1] == "}", "the try/catch must be the whole of the skipped block"
    assert not re.search(r"Read-Fast|\$CmdletsOnly", "\n".join(lines[close + 1:])), "nothing after the block may go fast"
    case = _op_case(script, "Compare")
    cmdlet_side = [l for l in _code_lines(case) if "$cmdletProfiles[[string]" in l]
    assert cmdlet_side == ["foreach ($row in @((Get-ProfileStates -CmdletsOnly).Rows)) { $cmdletProfiles[[string]$row.Name] = $row }"]
    fast_side = [l for l in _code_lines(case) if "$fastProfiles[[string]" in l]
    assert fast_side == ["foreach ($row in @(Read-FastProfileStates)) { $fastProfiles[[string]$row.Name] = $row }"]


def test_the_sentinel_is_named_in_one_place():
    """One code line names it, so that a change of name is one edit and cannot leave a second, older name behind."""
    lines = _code_lines(_ps1())
    named = [l for l in lines if "NoSuchStore" in l]
    assert len(named) == 1 and named[0].startswith("$sentinel = & $optionsOf '"), named


def test_the_sentinel_name_cannot_be_a_computer_or_a_path():
    """Measured on the VM: an unknown store is taken for a computer name (-PolicyStore <computer name> addresses its
    GPO store). TDC-NoSuchStore cost up to 5.2 s per read and put an AAAA query for it on the wire inside the captured
    chamber; not-a-store.invalid queried DNS too. A | can be in no computer name and no path, so the provider refuses
    the name on its syntax: 46 ms typically, no DNS. A plain name must not come back."""
    lines = _code_lines(_function_body(_ps1(), "Read-FastProfileStates"))
    sentinel = [l for l in lines if l.startswith("$sentinel = & $optionsOf '")]
    assert len(sentinel) == 1, sentinel
    name = re.search(r"& \$optionsOf '([^']*)'", sentinel[0]).group(1)
    assert "|" in name, "the sentinel %r could be a computer or a path name, and is then looked for on the network" % name
    assert name not in ("ActiveStore", "PersistentStore", "RSOP", "SystemDefaults", "StaticServiceStore",
                        "ConfigurableServiceStore", "localhost", ".")
    # measured: an empty store name answers with all three profiles, exactly like no option at all
    assert name.strip(), "an empty sentinel answers like no option and proves nothing"
