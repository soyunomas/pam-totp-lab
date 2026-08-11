#!/usr/bin/env python3

import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "pam_totp_enroll.py"
spec = importlib.util.spec_from_file_location("pam_totp_enroll", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TotpTests(unittest.TestCase):
    def test_rfc6238_sha1_vector(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(mod.totp_at(secret, 59, digits=8), "94287082")

    def test_verify_window_and_format(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        now = 1234567890
        self.assertTrue(mod.verify_totp(secret, mod.totp_at(secret, now), now=now))
        self.assertTrue(mod.verify_totp(secret, mod.totp_at(secret, now - 30), now=now))
        self.assertTrue(mod.verify_totp(secret, mod.totp_at(secret, now + 30), now=now))
        self.assertFalse(mod.verify_totp(secret, mod.totp_at(secret, now + 60), now=now))
        self.assertFalse(mod.verify_totp(secret, "12345x", now=now))

    def test_otpauth_uri_is_encoded(self):
        uri = mod.build_otpauth_uri("ABC234", "Lab Mint", "ana+test@example.com")
        self.assertIn("otpauth://totp/Lab%20Mint%3Aana%2Btest%40example.com?", uri)
        self.assertIn("secret=ABC234", uri)
        self.assertIn("issuer=Lab+Mint", uri)
        self.assertIn("algorithm=SHA1", uri)
        self.assertIn("digits=6", uri)
        self.assertIn("period=30", uri)

    def test_generate_secret_shape(self):
        with mock.patch.object(mod.secrets, "token_bytes", return_value=b"x" * 20):
            secret = mod.generate_secret()
        self.assertEqual(len(secret), 32)
        self.assertNotIn("=", secret)


class QrTests(unittest.TestCase):
    def test_qr_uri_goes_through_stdin_not_argv(self):
        uri = "otpauth://totp/x?secret=TOPSECRET234"
        with mock.patch.object(mod.shutil, "which", return_value="/usr/bin/qrencode"), \
             mock.patch.object(mod.subprocess, "run") as run:
            mod.show_qr(uri)
        args = run.call_args.args[0]
        self.assertNotIn(uri, args)
        self.assertNotIn("TOPSECRET234", " ".join(args))
        self.assertEqual(run.call_args.kwargs["input"], uri)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_missing_qrencode_fails_closed(self):
        with mock.patch.object(mod.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                mod.show_qr("otpauth://totp/x?secret=ABC234")


class FileTests(unittest.TestCase):
    def test_write_secret_mode_and_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".google_authenticator"
            mod.write_secret(path, "ABC234")
            self.assertEqual(path.read_text(encoding="ascii"), "ABC234\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_refuses_existing_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            path.write_text("OLD\n", encoding="ascii")
            with self.assertRaises(FileExistsError):
                mod.write_secret(path, "NEW234")
            self.assertEqual(path.read_text(encoding="ascii"), "OLD\n")

    def test_force_replaces_symlink_itself_not_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("DO NOT TOUCH\n", encoding="ascii")
            link = root / "secret"
            link.symlink_to(target)
            mod.write_secret(link, "NEW234", force=True)
            self.assertFalse(link.is_symlink())
            self.assertEqual(link.read_text(encoding="ascii"), "NEW234\n")
            self.assertEqual(target.read_text(encoding="ascii"), "DO NOT TOUCH\n")


class MainFlowTests(unittest.TestCase):
    @mock.patch.object(mod, "show_qr")
    @mock.patch.object(mod, "generate_secret", return_value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    def test_success_only_writes_after_verified_code(self, _gen, show_qr):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "secret"
            now = 1234567890
            code = mod.totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now)
            with mock.patch.object(mod.time, "time", return_value=now), \
                 mock.patch.object(mod.getpass, "getpass", return_value=code):
                rc = mod.main(["--issuer", "Mint", "--account", "alice", "--output", str(output)])
            self.assertEqual(rc, 0)
            self.assertTrue(output.exists())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            qr_uri = show_qr.call_args.args[0]
            self.assertIn("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", qr_uri)

    @mock.patch.object(mod, "show_qr")
    @mock.patch.object(mod, "generate_secret", return_value="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    def test_wrong_codes_never_write(self, _gen, _show_qr):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "secret"
            with mock.patch.object(mod.getpass, "getpass", return_value="000000"):
                rc = mod.main(["--output", str(output)])
            self.assertEqual(rc, 2)
            self.assertFalse(output.exists())

    @mock.patch.object(mod, "generate_secret")
    def test_existing_file_stops_before_generating_secret(self, generate_secret):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "secret"
            output.write_text("EXISTING\n", encoding="ascii")
            rc = mod.main(["--output", str(output)])
            self.assertEqual(rc, 1)
            generate_secret.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
