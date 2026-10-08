#!/usr/bin/env python3
"""Read-only readiness check for a test tablet connected over ADB.

Tells you whether a tablet can be enrolled in CryptSat MDM (Android Management API) and what to do first.
It CHANGES NOTHING on the tablet: it only runs the read-only commands in READ_ONLY_COMMANDS below, and refuses
to run anything else. It never installs, resets, enrols or reboots.

    python3 tablet_check.py                      # one tablet connected
    python3 tablet_check.py -s <adb serial>      # several connected
    python3 tablet_check.py --protected field_tablets.csv   # also check against the field-tablet list
    python3 tablet_check.py --json               # machine-readable report

Needs only Python 3 and adb (Linux: sudo apt install adb). USB debugging must be on and the computer
approved on the tablet ("Allow USB debugging?" prompt).

Facts used (developers.google.com/android/management/provision-device, checked 2026-10-08): QR enrolment needs
Android 7.0+ on a new or factory-reset device (tap the welcome screen six times); afw#setup at the Google
sign-in step works too and allows typing the enrolment token instead of scanning.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Any

# The only commands this tool will ever send to a tablet. All of them only read.
READ_ONLY_COMMANDS: dict[str, list[str]] = {
    "manufacturer": ["shell", "getprop", "ro.product.manufacturer"],
    "model": ["shell", "getprop", "ro.product.model"],
    "android": ["shell", "getprop", "ro.build.version.release"],
    "sdk": ["shell", "getprop", "ro.build.version.sdk"],
    "patch": ["shell", "getprop", "ro.build.version.security_patch"],
    "serial_prop": ["shell", "getprop", "ro.serialno"],
    "serial_boot": ["shell", "getprop", "ro.boot.serialno"],
    "gms": ["shell", "pm", "list", "packages", "com.google.android.gms"],
    "play_store": ["shell", "pm", "list", "packages", "com.android.vending"],
    "device_policy": ["shell", "pm", "list", "packages", "com.google.android.apps.work.clouddpc"],
    "owners": ["shell", "dpm", "list-owners"],
    "users": ["shell", "pm", "list", "users"],
    "setup_complete": ["shell", "settings", "get", "secure", "user_setup_complete"],
    "provisioned": ["shell", "settings", "get", "global", "device_provisioned"],
    "camera": ["shell", "pm", "list", "features"],
    "accounts": ["shell", "dumpsys", "account"],
}

Runner = Callable[[list[str]], tuple[int, str]]


def adb_runner(serial: str | None) -> Runner:
    def run(args: list[str]) -> tuple[int, str]:
        cmd = ["adb"] + (["-s", serial] if serial else []) + args
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            return 124, ""
        return p.returncode, (p.stdout or "").strip()
    return run


def query(run: Runner, key: str) -> str:
    if key not in READ_ONLY_COMMANDS:            # belt and braces: nothing outside the list, ever
        raise ValueError(f"not a read-only command: {key}")
    code, out = run(READ_ONLY_COMMANDS[key])
    return out if code == 0 else ""


def list_devices(run_host: Callable[[list[str]], tuple[int, str]]) -> list[tuple[str, str]]:
    code, out = run_host(["devices"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    return rows


def load_protected(path: str) -> set[str]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        col = next((c for c in (reader.fieldnames or []) if c.lower().replace("_", "") == "serialnumber"), None)
        if col is None:
            raise SystemExit(f"{path}: no serialNumber column found")
        return {r[col].strip().upper() for r in reader if r.get(col, "").strip()}


def check(run: Runner, adb_serial: str = "", protected: set[str] | None = None) -> dict[str, Any]:
    info = {k: query(run, k) for k in READ_ONLY_COMMANDS}
    serial = info["serial_prop"] or info["serial_boot"] or adb_serial
    sdk = int(info["sdk"]) if info["sdk"].isdigit() else 0
    owners = info["owners"]
    has_device_owner = "device owner" in owners.lower() or "deviceowner" in owners.lower().replace(" ", "")
    has_profile_owner = "profile owner" in owners.lower()
    work_profile = sum(1 for line in info["users"].splitlines() if "UserInfo{" in line) > 1
    setup_done = info["setup_complete"] == "1" or info["provisioned"] == "1"
    google_accounts = info["accounts"].count("type=com.google")

    report: dict[str, Any] = {
        "tablet": {
            "manufacturer": info["manufacturer"], "model": info["model"], "android": info["android"],
            "sdk": sdk, "security_patch": info["patch"], "serial": serial,
        },
        "checks": [], "verdict": "", "next_steps": [],
    }
    checks = report["checks"]

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    stop = False
    if protected is not None:
        if serial and serial.upper() in protected:
            add("Not a field tablet", "STOP", f"serial {serial} is on the field-tablet list. Do not reset or enrol it.")
            stop = True
        elif not serial:
            add("Not a field tablet", "WARN", "could not read the serial number to compare with the list")
        else:
            add("Not a field tablet", "OK", "serial not on the field-tablet list")

    if sdk >= 24:
        add("Android version", "OK", f"Android {info['android']} (API {sdk}): QR enrolment supported (needs 7.0+)")
    elif sdk >= 23:
        add("Android version", "WARN", f"Android {info['android']}: below 7.0, so no QR; afw#setup or NFC only")
    else:
        add("Android version", "STOP", f"Android {info['android'] or 'unknown'}: too old for this enrolment")
        stop = True

    if info["gms"] and info["play_store"]:
        add("Google Play services", "OK", "Google Play services and Play Store present")
    else:
        add("Google Play services", "STOP", "Google Play services or Play Store missing; Android Device Policy "
                                            "comes from Google Play")
        stop = True

    if has_device_owner:
        add("Existing management", "STOP", "the tablet already has a device owner (managed by something else). "
                                           f"Find out what before touching it. dpm says: {owners[:200]}")
        stop = True
    elif has_profile_owner or work_profile:
        add("Existing management", "WARN", "a work profile or profile owner exists; a factory reset removes it")
    else:
        add("Existing management", "OK", "no device owner or work profile")

    if info["device_policy"]:
        add("Android Device Policy", "WARN", "Google's management app is already installed; it may be enrolled "
                                             "somewhere already")

    if "android.hardware.camera" in info["camera"]:
        add("Camera for QR", "OK", "camera present")
    else:
        add("Camera for QR", "WARN", "no camera found; use afw#setup and type the enrolment token")

    if setup_done:
        add("Setup state", "INFO", f"setup is already complete ({google_accounts} Google account(s) on it). "
                                   "Enrolment needs a factory reset, which ERASES EVERYTHING on the tablet.")
    else:
        add("Setup state", "OK", "setup wizard not finished: ready for enrolment without a reset")

    if stop:
        report["verdict"] = "NOT READY"
        report["next_steps"] = ["Fix the STOP items above. Do not reset or enrol this tablet until they are clear."]
    else:
        report["verdict"] = "READY (after a factory reset)" if setup_done else "READY"
        steps = []
        if setup_done:
            steps.append("Copy off anything you need, remove Google accounts (avoids a factory-reset-protection "
                         "lock), then factory reset from Settings.")
        steps += [
            "Wait for the CryptSat enrolment QR code (needs Google's quota approval and the lab tenant).",
            "On the welcome screen, tap the same spot six times, connect Wi-Fi, scan the QR code.",
            "Or: at the Google sign-in step type afw#setup and enter the enrolment token.",
        ]
        report["next_steps"] = steps
    return report


def render(report: dict[str, Any]) -> str:
    t = report["tablet"]
    lines = [f"Tablet: {t['manufacturer']} {t['model']}  Android {t['android']} (API {t['sdk']})  "
             f"patch {t['security_patch'] or '?'}  serial {t['serial'] or '?'}", ""]
    for c in report["checks"]:
        lines.append(f"  [{c['status']:<4}] {c['check']}: {c['detail']}")
    lines += ["", f"Verdict: {report['verdict']}", ""]
    lines += [f"  {i}. {s}" for i, s in enumerate(report["next_steps"], 1)]
    lines += ["", "Nothing on the tablet was changed."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only CryptSat enrolment readiness check (changes nothing).")
    ap.add_argument("-s", "--serial", help="adb serial, when more than one device is connected")
    ap.add_argument("--protected", help="CSV of field-tablet serials (GAM export with a serialNumber column)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)

    if not shutil.which("adb"):
        print("adb not found. On Ubuntu: sudo apt install adb", file=sys.stderr)
        return 2

    def host(args: list[str]) -> tuple[int, str]:
        p = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=20)
        return p.returncode, p.stdout.strip()

    devices = list_devices(host)
    if a.serial:
        devices = [d for d in devices if d[0] == a.serial]
    if not devices:
        print("No tablet found. Plug it in, turn on USB debugging, and accept the prompt on the tablet.",
              file=sys.stderr)
        return 2
    if len(devices) > 1:
        print("Several devices connected; choose one with -s:\n" + "\n".join(f"  {s}  {st}" for s, st in devices),
              file=sys.stderr)
        return 2
    adb_serial, state = devices[0]
    if state != "device":
        print(f"Tablet {adb_serial} is '{state}'. If 'unauthorized', unlock it and accept the "
              "'Allow USB debugging?' prompt.", file=sys.stderr)
        return 2

    protected = load_protected(a.protected) if a.protected else None
    report = check(adb_runner(adb_serial), adb_serial, protected)
    print(json.dumps(report, indent=2) if a.json else render(report))
    return 1 if report["verdict"] == "NOT READY" else 0


if __name__ == "__main__":
    sys.exit(main())
