"""Synthetic, offline release-audit tests; no real GitHub assets or Macs used."""
import io
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "audit-cli-release.py"
ARCHES = {"aarch64": 0x0100000C, "x86_64": 0x01000007}


class AuditReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.downloads = self.path / "assets"
        self.downloads.mkdir()
        self.bin = self.path / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, sys\n'
            'with open(os.environ["AUDIT_GH_LOG"], "a") as f:\n'
            '    f.write(json.dumps(sys.argv[1:]) + "\\n")\n'
            'if sys.argv[1:3] == ["release", "view"]:\n'
            '    print(json.dumps({"tagName": "applesauce-cli/v0.5.31", "isDraft": False}))\n'
            'elif os.getenv("AUDIT_GH_FAIL") == sys.argv[1]:\n'
            '    sys.exit(3)\n',
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self.log = self.path / "gh.log"
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            AUDIT_GH_LOG=str(self.log),
        )
        for arch, cpu in ARCHES.items():
            self.make_archive(arch, cpu)

    def make_archive(self, arch, cpu, *, symlink=False):
        path = self.downloads / f"applesauce-cli-v0.5.31-{arch}-apple-darwin.tar.xz"
        with tarfile.open(path, "w:xz") as tar:
            data = b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + b"\0" * 64
            member = tarfile.TarInfo("applesauce-cli/applesauce")
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                tar.addfile(member)
            else:
                member.size = len(data)
                member.mode = 0o755
                tar.addfile(member, io.BytesIO(data))
        return path

    def run_audit(self):
        return subprocess.run(
            ["python3", str(SCRIPT), str(self.downloads)],
            text=True, capture_output=True, env=self.env,
        )

    def calls(self):
        import json
        return [
            json.loads(line) for line in self.log.read_text().splitlines()
        ] if self.log.exists() else []

    def test_both_architectures_hashes_and_exact_sha_attestation(self):
        run = self.run_audit()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('"aarch64"', run.stdout)
        self.assertIn('"x86_64"', run.stdout)
        self.assertIn("source_sha", run.stdout)
        calls = self.calls()
        self.assertEqual(len(calls), 5)
        self.assertEqual(sum(c[:2] == ["release", "verify-asset"] for c in calls), 2)
        attestations = [c for c in calls if c[:2] == ["attestation", "verify"]]
        self.assertEqual(len(attestations), 2)
        for args in attestations:
            self.assertIn("1585dceb6c745cebf822588526ee5005255818c9", args)
            self.assertIn("refs/tags/applesauce-cli/v0.5.31", args)
            self.assertIn("chriscoveriesorg/applesauce/.github/workflows/applesauce-cli-release.yml", args)

    def test_wrong_cpu_fails(self):
        self.make_archive("aarch64", ARCHES["x86_64"])
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("Mach-O CPU", run.stderr)

    def test_missing_or_duplicated_architecture_fails(self):
        (self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz").unlink()
        self.assertIn("exactly one aarch64", self.run_audit().stderr)
        self.make_archive("aarch64", ARCHES["aarch64"])
        path = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("applesauce")
            data = b"any binary"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        self.assertIn("exactly one aarch64", self.run_audit().stderr)

    def test_symlink_executable_fails_before_provenance(self):
        self.make_archive("aarch64", ARCHES["aarch64"], symlink=True)
        self.assertIn("missing or unsafe", self.run_audit().stderr)

    def test_corrupt_archive_fails(self):
        path = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        path.write_bytes(b"fake archive")
        self.assertIn("cannot read tar archive", self.run_audit().stderr)

    def test_missing_or_failed_provenance_fails_closed(self):
        self.env["AUDIT_GH_FAIL"] = "attestation"
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("gh command failed", run.stderr)
        self.assertNotIn("verified. Signed", run.stdout)
        self.env["AUDIT_GH_FAIL"] = "release"
        # The mock release-view path deliberately emits a response, so only
        # release asset verification is allowed to fail for this check.
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)

    def test_does_not_extract_archive_contents(self):
        self.make_archive("aarch64", ARCHES["aarch64"], symlink=True)
        self.run_audit()
        self.assertFalse((self.path / "outside").exists())
        self.assertFalse((self.downloads / "applesauce").exists())


if __name__ == "__main__":
    unittest.main()
