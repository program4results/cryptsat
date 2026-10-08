"""Pure unit tests: no database."""
import pytest

from app import amapi, auth, config, policy, rings


def test_ring_buckets_are_stable_and_nested():
    ids = [f"dev{i}" for i in range(2000)]
    r5 = {i for i in ids if rings.selected("sl", i, "r5", set())}
    r25 = {i for i in ids if rings.selected("sl", i, "r25", set())}
    r100 = {i for i in ids if rings.selected("sl", i, "r100", set())}
    assert r5 <= r25 <= r100 and r100 == set(ids)
    assert 40 <= len(r5) <= 160          # about 5% of 2,000
    assert rings.bucket("sl", "dev1") == rings.bucket("sl", "dev1")
    assert not any(rings.selected("sl", i, "pilot", set()) for i in ids)
    assert rings.selected("sl", "dev1", "pilot", {"dev1"})


def test_ring_order():
    assert rings.next_stage("pilot") == "r5" and rings.next_stage("r100") is None
    assert rings.is_forward("r5", "r25") and not rings.is_forward("r25", "pilot")
    with pytest.raises(ValueError):
        rings.selected("sl", "x", "r50", set())


def test_policy_validation():
    assert policy.validate(policy.TEMPLATES["baseline"]) == []
    assert policy.validate({"wipeDataFlags": ["X"]}) == ["unknown policy key: wipeDataFlags"]
    assert policy.validate({"keyguardDisabled": True}) == ["forbidden setting: keyguardDisabled=True"]
    assert policy.validate({}) == ["policy must be a non-empty object"]
    assert policy.diff({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {"added": ["c"], "removed": ["a"], "changed": ["b"]}


def test_wipe_is_not_a_command():
    assert "WIPE" not in amapi.ALLOWED_COMMANDS
    with pytest.raises(ValueError):
        amapi.FakeAmapi().issue_command("enterprises/x/devices/1", "WIPE")


def test_unconfigured_amapi_fails_closed():
    with pytest.raises(amapi.NotConfigured):
        amapi.UnconfiguredAmapi().list_devices("enterprises/x")
    assert isinstance(amapi.make_client("none"), amapi.UnconfiguredAmapi)
    assert isinstance(amapi.make_client("google"), amapi.UnconfiguredAmapi)


def test_role_parsing():
    roles = auth.parse_roles("sl-mbsse:admin, gm-mobse:viewer, *:super_admin")
    p = auth.Principal("a", roles)
    assert p.is_super and p.can("anything", "admin")
    p = auth.Principal("b", auth.parse_roles("sl-mbsse:operator"))
    assert p.can("sl-mbsse", "viewer") and p.can("sl-mbsse", "operator") and not p.can("sl-mbsse", "admin")
    assert not p.can("gm-mobse", "viewer")
    r = auth.Principal("c", auth.parse_roles("sl-mbsse:reader"))
    assert r.can("sl-mbsse", "reader") and not r.can("sl-mbsse", "viewer")
    for bad in ("sl:super_admin", "*:admin", "SL:admin", "sl-mbsse:owner"):
        with pytest.raises(ValueError):
            auth.parse_roles(bad)


@pytest.mark.parametrize("var", ["CRYPTSAT_AUTH=dev", "CRYPTSAT_AMAPI=fake"])
def test_dev_settings_refused_in_production(monkeypatch, var):
    monkeypatch.setenv("CRYPTSAT_ENV", "production")
    monkeypatch.delenv("CRYPTSAT_AUTH", raising=False)
    monkeypatch.delenv("CRYPTSAT_AMAPI", raising=False)
    k, v = var.split("=")
    monkeypatch.setenv(k, v)
    with pytest.raises(RuntimeError):
        config.check()


def test_real_google_mode_not_implemented(monkeypatch):
    monkeypatch.setenv("CRYPTSAT_ENV", "production")
    monkeypatch.setenv("CRYPTSAT_AMAPI", "google")
    with pytest.raises(RuntimeError):
        config.check()
