"""The ADB readiness check: verdicts, and proof that it only ever sends read-only commands."""
from __future__ import annotations

import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import tablet_check as tc  # noqa: E402

FRESH = {
    "manufacturer": "samsung", "model": "SM-X200", "android": "13", "sdk": "33", "patch": "2026-08-01",
    "serial_prop": "R9TT123ABC", "serial_boot": "", "gms": "package:com.google.android.gms",
    "play_store": "package:com.android.vending", "device_policy": "", "owners": "no owners",
    "users": "Users:\n\tUserInfo{0:Owner:c13} running", "setup_complete": "0", "provisioned": "0",
    "camera": "feature:android.hardware.camera\nfeature:android.hardware.wifi", "accounts": "",
}


def fake(values: dict[str, str]):
    sent: list[list[str]] = []
    reverse = {tuple(v): k for k, v in tc.READ_ONLY_COMMANDS.items()}

    def run(args):
        sent.append(args)
        return 0, values.get(reverse[tuple(args)], "")
    return run, sent


def statuses(report):
    return {c["check"]: c["status"] for c in report["checks"]}


def test_fresh_tablet_is_ready_and_only_reads():
    run, sent = fake(FRESH)
    r = tc.check(run)
    assert r["verdict"] == "READY" and r["tablet"]["serial"] == "R9TT123ABC"
    assert all(s == "OK" for s in statuses(r).values())
    assert all(args in tc.READ_ONLY_COMMANDS.values() for args in sent)


def test_used_tablet_needs_a_reset():
    run, _ = fake({**FRESH, "setup_complete": "1",
                   "accounts": "Account {name=a@gmail.com, type=com.google}"})
    r = tc.check(run)
    assert r["verdict"] == "READY (after a factory reset)"
    assert "ERASES EVERYTHING" in next(c["detail"] for c in r["checks"] if c["check"] == "Setup state")
    assert "remove Google accounts" in r["next_steps"][0]


@pytest.mark.parametrize("override,check", [
    ({"owners": "Device Owner: admin=ComponentInfo{com.other.mdm/.Admin}"}, "Existing management"),
    ({"gms": ""}, "Google Play services"),
    ({"sdk": "22", "android": "5.1"}, "Android version"),
])
def test_stop_conditions(override, check):
    run, _ = fake({**FRESH, **override})
    r = tc.check(run)
    assert r["verdict"] == "NOT READY" and statuses(r)[check] == "STOP"


def test_field_tablet_is_stopped(tmp_path):
    csv_file = tmp_path / "field.csv"
    csv_file.write_text("email,serialNumber,model\nx@y,r9tt123abc,SM-X200\n")
    run, _ = fake(FRESH)
    r = tc.check(run, protected=tc.load_protected(str(csv_file)))
    assert r["verdict"] == "NOT READY" and statuses(r)["Not a field tablet"] == "STOP"


def test_android_6_warns_no_qr():
    run, _ = fake({**FRESH, "sdk": "23", "android": "6.0"})
    r = tc.check(run)
    assert statuses(r)["Android version"] == "WARN" and r["verdict"] == "READY"


def test_refuses_anything_outside_the_list():
    with pytest.raises(ValueError):
        tc.query(lambda a: (0, ""), "reboot")


def test_end_to_end_with_a_fake_adb(tmp_path, monkeypatch, capsys):
    log = tmp_path / "adb.log"
    script = tmp_path / "adb"
    script.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        echo "$@" >> {log}
        case "$*" in
          devices) printf 'List of devices attached\\nABC123\\tdevice\\n' ;;
          *ro.build.version.sdk*) echo 33 ;;
          *ro.build.version.release*) echo 13 ;;
          *com.google.android.gms*) echo package:com.google.android.gms ;;
          *com.android.vending*) echo package:com.android.vending ;;
          *"pm list features"*) echo feature:android.hardware.camera ;;
          *) echo "" ;;
        esac
        """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert tc.main([]) == 0
    out = capsys.readouterr().out
    assert "Verdict: READY" in out and "Nothing on the tablet was changed." in out
    sent = [line.split() for line in log.read_text().splitlines()]
    allowed = [["devices"]] + [["-s", "ABC123", *a] for a in tc.READ_ONLY_COMMANDS.values()]
    assert all(cmd in allowed for cmd in sent), sent
