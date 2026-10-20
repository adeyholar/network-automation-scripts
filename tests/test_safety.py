"""Offline tests for the safety fixes. No firewall needed: requests is mocked."""
import importlib.util
import os
import sys
import types
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "paloalto", "common"))
import panos_safety  # noqa: E402


def load_cli():
    path = os.path.join(ROOT, "paloalto", "config-change-cli", "palo_config_change.py")
    spec = importlib.util.spec_from_file_location("palo_config_change", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RULE = """<response status="success"><result><entry name="r1">
<source><member>obj-a</member><member>obj-b</member></source>
<destination><member>obj-a</member></destination>
<service><member>any</member></service></entry></result></response>"""
RULE_OK = """<response status="success"><result><entry name="r2">
<source><member>obj-a</member><member>obj-b</member></source>
<destination><member>any</member></destination></entry></result></response>"""
WRITE_MARKERS = ("action=delete", "action=edit", "action=set", "type=commit", "type=import")


def fake_response(text):
    r = mock.Mock(); r.text = text; r.status_code = 200; r.raise_for_status = lambda: None
    return r


class MemberRemoval(unittest.TestCase):
    def test_removes_member_keeps_rule(self):
        entry = ET.fromstring(RULE_OK).find(".//entry")
        changed, blocked = panos_safety.remove_member_from_rule(entry, "obj-a")
        self.assertEqual(changed, ["source"]); self.assertEqual(blocked, [])
        self.assertEqual([m.text for m in entry.find("source")], ["obj-b"])

    def test_skips_when_field_would_be_empty(self):
        entry = ET.fromstring(RULE).find(".//entry")
        before = ET.tostring(entry)
        changed, blocked = panos_safety.remove_member_from_rule(entry, "obj-a")
        self.assertEqual(changed, []); self.assertEqual(blocked, ["destination"])
        self.assertEqual(ET.tostring(entry), before, "rule must be untouched when skipped")

    def test_never_deletes_rule_and_skip_makes_no_write(self):
        calls = []
        def req(method, url, **kw):
            calls.append((method, url)); return fake_response(RULE)
        with mock.patch("requests.request", side_effect=req):
            ok = panos_safety.remove_object_from_rule("fw.example.com", None, "k", "security", "r1", "obj-a", log=lambda *_: None)
        self.assertFalse(ok)
        self.assertEqual([m for m, _ in calls], ["GET"])

    def test_edit_not_delete(self):
        calls = []
        def req(method, url, **kw):
            calls.append((method, url)); return fake_response(RULE_OK)
        with mock.patch("requests.request", side_effect=req):
            ok = panos_safety.remove_object_from_rule("fw.example.com", None, "k", "security", "r2", "obj-a", log=lambda *_: None)
        self.assertTrue(ok)
        self.assertIn("action=edit", calls[-1][1]); self.assertNotIn("action=delete", calls[-1][1])


class Commit(unittest.TestCase):
    def test_partial_commit_xml(self):
        self.assertEqual(panos_safety.partial_commit_cmd("ops1"),
                         "<commit><partial><admin><member>ops1</member></admin></partial></commit>")

    def test_no_commit_without_confirmation(self):
        with mock.patch("requests.request") as req:
            ok = panos_safety.commit_own_changes("fw.example.com", None, "k", "ops1", confirm=lambda a: False, log=lambda *_: None)
        self.assertFalse(ok); req.assert_not_called()

    def test_commit_is_partial(self):
        with mock.patch("requests.request", return_value=fake_response('<response status="success"/>')) as req:
            ok = panos_safety.commit_own_changes("fw.example.com", None, "k", "ops1", confirm=lambda a: True, log=lambda *_: None)
        self.assertTrue(ok)
        url = req.call_args[0][1]
        self.assertIn("partial", url); self.assertIn("ops1", url)


class TLS(unittest.TestCase):
    def test_default_on(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIs(panos_safety.configure_tls(log=lambda *_: None), True)

    def test_env_off_warns(self):
        msgs = []
        with mock.patch.dict(os.environ, {"NET_SCRIPTS_VERIFY_TLS": "false"}, clear=True):
            self.assertIs(panos_safety.configure_tls(log=msgs.append), False)
        self.assertTrue(any("WARNING" in m for m in msgs))

    def test_insecure_flag_and_ca_bundle(self):
        self.assertIs(panos_safety.configure_tls(insecure=True, log=lambda *_: None), False)
        with mock.patch.dict(os.environ, {"NET_SCRIPTS_CA_BUNDLE": __file__}, clear=True):
            self.assertEqual(panos_safety.configure_tls(log=lambda *_: None), __file__)
        panos_safety.configure_tls(log=lambda *_: None)

    def test_no_verify_false_left(self):
        for d, _, files in os.walk(ROOT):
            if ".git" in d:
                continue
            for f in files:
                if f.endswith(".py") and f != "test_safety.py":
                    with open(os.path.join(d, f), encoding="utf-8") as fh:
                        self.assertNotIn("verify=False", fh.read(), f)


class CLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = load_cli()

    def test_dry_run_makes_no_writes(self):
        cli = self.cli
        urls = []
        def get(url, **kw):
            urls.append(url)
            return fake_response(RULE_OK if "rulebase" in url else '<response status="success"><result/></response>')
        def post(url, **kw):
            urls.append(url); return fake_response('<response status="success"/>')
        def request(method, url, **kw):
            urls.append(url); return fake_response(RULE_OK)
        usage = {"obj-a": {"security_policies": ["r2"], "nat_rules": [], "address_groups": []}}
        with mock.patch.object(cli, "DRY_RUN", True), \
             mock.patch("requests.get", side_effect=get), mock.patch("requests.post", side_effect=post), \
             mock.patch("requests.request", side_effect=request), mock.patch("builtins.print"):
            ok, failed = cli.delete_batch_objects("fw.example.com", None, ["obj-a"], usage, "k")
        self.assertEqual(failed, [])
        self.assertTrue(urls, "expected read calls")
        for u in urls:
            self.assertFalse(any(w in u for w in WRITE_MARKERS), u)

    def test_backup_does_not_commit(self):
        cli = self.cli
        urls = []
        def get(url, **kw):
            urls.append(url); r = fake_response("<response><result><hostname>fw</hostname></result></response>"); r.content = b"<config/>"; return r
        with mock.patch("requests.get", side_effect=get), mock.patch("requests.post") as post, \
             mock.patch("builtins.open", mock.mock_open()), mock.patch("builtins.print"):
            cli.download_running_config("fw.example.com", None, "k")
        post.assert_not_called()
        self.assertFalse(any("commit" in u for u in urls))

    def test_countdown_ctrl_c_returns_to_menu(self):
        def sleep(_):
            raise KeyboardInterrupt
        with mock.patch("builtins.print"):
            self.assertTrue(self.cli.exit_countdown(total_seconds=5, sleep=sleep))

    def test_countdown_completes(self):
        t = iter(range(0, 100))
        with mock.patch("builtins.print"):
            self.assertFalse(self.cli.exit_countdown(total_seconds=3, sleep=lambda _: None, clock=lambda: next(t)))


class PolicyAPI(unittest.TestCase):
    def test_keygen_response_not_printed(self):
        fake_fastapi = types.ModuleType("fastapi")
        class HTTPException(Exception):
            def __init__(self, status_code=None, detail=None): super().__init__(detail)
        class FastAPI:
            def __getattr__(self, name): return lambda *a, **k: (lambda f: f)
        fake_fastapi.FastAPI = FastAPI; fake_fastapi.HTTPException = HTTPException
        env = {"PANOS_HOST": "192.0.2.1", "PANOS_USERNAME": "u", "PANOS_PASSWORD": "p"}
        path = os.path.join(ROOT, "paloalto", "policy-api", "policy_export_api.py")
        with mock.patch.dict(sys.modules, {"fastapi": fake_fastapi}), mock.patch.dict(os.environ, env), \
             mock.patch("builtins.print"):
            spec = importlib.util.spec_from_file_location("pea", path)
            mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        secret = "SECRETKEY123"
        printed = []
        with mock.patch("requests.post", return_value=fake_response(f"<response><result><key>{secret}</key></result></response>")), \
             mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))):
            self.assertEqual(mod.get_api_key(), secret)
        self.assertFalse(any(secret in p for p in printed))
        self.assertFalse(hasattr(mod, "undo_policy"))


if __name__ == "__main__":
    unittest.main()
