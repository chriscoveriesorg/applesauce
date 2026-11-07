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
SUBTYPES = {"aarch64": 0, "x86_64": 3}


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

    def make_archive(self, arch, cpu, *, symlink=False, filetype=2,
                     name="applesauce-cli/applesauce", mode=0o755,
                     bad_load_size=False, extra_link=False, extra_members=(),
                     subtype=None, platform=1):
        path = self.downloads / f"applesauce-cli-v0.5.31-{arch}-apple-darwin.tar.xz"
        with tarfile.open(path, "w:xz") as tar:
            if platform is None:
                command = struct.pack("<II", 2, 8)  # no OS marker
            elif platform == "legacy":
                command = struct.pack("<4I", 0x24, 16, 0x000A0F00, 0x000A0F00)
            else:
                command = struct.pack(
                    "<6I", 0x32, 7 if bad_load_size else 24,
                    platform, 0x000B0000, 0x000B0000, 0,
                )
            default_subtype = next(
                (SUBTYPES[arch] for arch, target in ARCHES.items() if cpu == target), 0
            )
            data = (b"\xcf\xfa\xed\xfe"
                    + struct.pack("<7I", cpu,
                                  default_subtype if subtype is None else subtype,
                                  filetype, 1, len(command), 0, 0)
                    + command + b"\0" * 64)
            member = tarfile.TarInfo(name)
            member.mode = mode
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                tar.addfile(member)
            else:
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            if extra_link:
                link = tarfile.TarInfo("applesauce-cli/unsafe-link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../../outside"
                tar.addfile(link)
            for extra_name, kind in extra_members:
                extra = tarfile.TarInfo(extra_name)
                if kind == "directory":
                    extra.type = tarfile.DIRTYPE
                    extra.mode = 0o755
                    tar.addfile(extra)
                else:
                    data = b"extra fixture contents"
                    extra.size = len(data)
                    tar.addfile(extra, io.BytesIO(data))
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

    def test_executable_at_unexpected_path_is_refused(self):
        self.make_archive(
            "aarch64", ARCHES["aarch64"], name="other/applesauce",
        )
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("unexpected executable path", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_rejects_nonportable_macho_cpu_subtypes(self):
        for arch, cpu, subtype in (
            ("aarch64", ARCHES["aarch64"], 2),  # arm64e, not baseline arm64
            ("x86_64", ARCHES["x86_64"], 8),  # x86_64h, not baseline x86_64
            ("x86_64", ARCHES["x86_64"], 0x01000003),  # unknown feature flags
        ):
            with self.subTest(arch=arch, subtype=subtype):
                self.make_archive(arch, cpu, subtype=subtype)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("Mach-O CPU subtype", run.stderr)

    def test_rejects_foreign_or_missing_macos_platform_marker(self):
        for platform in (2, 6, None):  # iOS, Catalyst, missing marker
            with self.subTest(platform=platform):
                self.make_archive("aarch64", ARCHES["aarch64"], platform=platform)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("Mach-O", run.stderr)

    def test_accepts_legacy_macos_marker_and_baseline_cpu_capability(self):
        self.make_archive("x86_64", ARCHES["x86_64"],
                          subtype=0x80000003, platform="legacy")
        run = self.run_audit()
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_dynamic_library_header_is_refused(self):
        self.make_archive("x86_64", ARCHES["x86_64"], filetype=6)
        self.assertIn("expected executable", self.run_audit().stderr)

    def test_symlinked_download_is_refused(self):
        target = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        real = self.path / "outside-archive.tar.xz"
        target.rename(real)
        target.symlink_to(real)
        self.assertIn("exactly one aarch64", self.run_audit().stderr)

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
        self.assertIn("unsafe tar member type", self.run_audit().stderr)

    def test_corrupt_archive_fails(self):
        path = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        path.write_bytes(b"fake archive")
        self.assertIn("cannot read tar archive", self.run_audit().stderr)

    def test_archive_path_traversal_and_absolute_names_are_refused(self):
        for unsafe in ("../../applesauce", "/tmp/applesauce",
                       "applesauce-cli/../applesauce",
                       "applesauce-cli//applesauce",
                       r"applesauce-cli\applesauce"):
            with self.subTest(path=unsafe):
                self.make_archive("aarch64", ARCHES["aarch64"], name=unsafe)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("unsafe archive member path", run.stderr)

    def test_duplicate_nonbinary_archive_path_is_refused(self):
        path = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        with tarfile.open(path, "w:xz") as tar:
            for content in (b"first", b"second"):
                member = tarfile.TarInfo("applesauce-cli/README")
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("duplicate archive member path", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"] for c in self.calls()))

    def test_macos_case_insensitive_collision_is_refused(self):
        # On common macOS volumes a case-only alias could overwrite an
        # executable after the one we verified.
        self.make_archive(
            "aarch64", ARCHES["aarch64"],
            extra_members=[("applesauce-cli/APPLESAUCE", "file")],
        )
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("collides on macOS", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_macos_unicode_normalization_collision_is_refused(self):
        self.make_archive(
            "aarch64", ARCHES["aarch64"],
            extra_members=[
                ("applesauce-cli/résumé.txt", "file"),
                ("applesauce-cli/re\u0301sume\u0301.txt", "file"),
            ],
        )
        self.assertIn("collides on macOS", self.run_audit().stderr)

    def test_file_as_ancestor_of_extracted_member_is_refused(self):
        self.make_archive(
            "aarch64", ARCHES["aarch64"],
            extra_members=[("applesauce-cli/applesauce/docs", "file")],
        )
        self.assertIn("file obstructs nested path", self.run_audit().stderr)

    def test_file_overwriting_implicit_directory_is_refused(self):
        self.make_archive(
            "aarch64", ARCHES["aarch64"],
            extra_members=[("applesauce-cli", "file")],
        )
        self.assertIn("file conflicts with directory", self.run_audit().stderr)

    def test_explicit_directories_with_safe_nested_files_are_allowed(self):
        self.make_archive(
            "aarch64", ARCHES["aarch64"],
            extra_members=[
                ("applesauce-cli", "directory"),
                ("applesauce-cli/docs", "directory"),
                ("applesauce-cli/docs/README", "file"),
            ],
        )
        run = self.run_audit()
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_secondary_symlink_in_archive_is_refused(self):
        self.make_archive("aarch64", ARCHES["aarch64"], extra_link=True)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("unsafe tar member type", run.stderr)

    def test_privileged_executable_mode_is_refused_before_provenance(self):
        for mode in (0o4755, 0o2755, 0o1755):
            with self.subTest(mode=oct(mode)):
                self.make_archive("aarch64", ARCHES["aarch64"], mode=mode)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("unsafe archive member permissions", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_executable_bit_required_for_installed_binary(self):
        self.make_archive("aarch64", ARCHES["aarch64"], mode=0o644)
        self.assertIn("invalid or writable executable mode", self.run_audit().stderr)

    def test_group_or_world_writable_executable_is_refused(self):
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.make_archive("aarch64", ARCHES["aarch64"], mode=mode)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("invalid or writable executable mode", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_malformed_macho_load_command_is_refused(self):
        self.make_archive("aarch64", ARCHES["aarch64"], bad_load_size=True)
        self.assertIn("invalid Mach-O load command size", self.run_audit().stderr)

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
