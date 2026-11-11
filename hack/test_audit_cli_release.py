"""Synthetic, offline release-audit tests; no real GitHub assets or Macs used."""
import hashlib
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
            '    sys.exit(3)\n'
            'elif sys.argv[1] == "api":\n'
            '    print(json.dumps({"ref": os.getenv("AUDIT_TAG_REF", "refs/tags/applesauce-cli/v0.5.31"),\n'
            '        "object": {"type": os.getenv("AUDIT_TAG_TYPE", "commit"),\n'
            '                   "sha": os.getenv("AUDIT_TAG_SHA", "1585dceb6c745cebf822588526ee5005255818c9")}}))\n',
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
                     subtype=None, platform=1, build_tool_count=0,
                     entry_offset=96, duplicate_entry=False, reserved=0,
                     unknown_command_size=None, legacy_extra_bytes=0):
        path = self.downloads / f"applesauce-cli-v0.5.31-{arch}-apple-darwin.tar.xz"
        with tarfile.open(path, "w:xz") as tar:
            if platform is None:
                command = struct.pack("<II", 2, 8)  # no OS marker
            elif platform == "legacy":
                command = (struct.pack("<4I", 0x24, 16 + legacy_extra_bytes,
                                       0x000A0F00, 0x000A0F00)
                           + b"\0" * legacy_extra_bytes)
            else:
                command = struct.pack(
                    "<6I", 0x32, 7 if bad_load_size else 24,
                    platform, 0x000B0000, 0x000B0000, build_tool_count,
                )
            if entry_offset is not None:
                command += struct.pack("<IIQQ", 0x80000028, 24, entry_offset, 0)
            if duplicate_entry:
                if entry_offset is None:
                    raise ValueError("duplicate_entry requires entry_offset")
                command += struct.pack("<IIQQ", 0x80000028, 24, entry_offset, 0)
            # Unknown LC_* commands may appear in newer SDKs. They are
            # permitted when structurally valid, including 8-byte alignment.
            if unknown_command_size is not None:
                if not 8 <= unknown_command_size <= 64:
                    raise ValueError("unknown command size must be 8..64")
                command += struct.pack("<II", 0x71234567, unknown_command_size)
                command += b"\0" * (unknown_command_size - 8)
            default_subtype = next(
                (SUBTYPES[arch] for arch, target in ARCHES.items() if cpu == target), 0
            )
            data = (b"\xcf\xfa\xed\xfe"
                    + struct.pack("<7I", cpu,
                                  default_subtype if subtype is None else subtype,
                                  filetype, 1 + (entry_offset is not None)
                                  + duplicate_entry
                                  + (unknown_command_size is not None),
                                  len(command), 0, reserved)
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
        self.assertEqual(run.stdout.count('"executable_sha256"'), 2)
        for arch in ARCHES:
            asset = self.downloads / f"applesauce-cli-v0.5.31-{arch}-apple-darwin.tar.xz"
            with tarfile.open(asset, "r:xz") as tar:
                payload = tar.extractfile("applesauce-cli/applesauce").read()
            self.assertIn(hashlib.sha256(payload).hexdigest(), run.stdout)
        calls = self.calls()
        self.assertEqual(len(calls), 6)
        self.assertEqual(sum(c[0] == "api" for c in calls), 1)
        self.assertEqual(sum(c[:2] == ["release", "verify-asset"] for c in calls), 2)
        attestations = [c for c in calls if c[:2] == ["attestation", "verify"]]
        self.assertEqual(len(attestations), 2)
        for args in attestations:
            self.assertIn("1585dceb6c745cebf822588526ee5005255818c9", args)
            self.assertIn("refs/tags/applesauce-cli/v0.5.31", args)
            self.assertIn("chriscoveriesorg/applesauce/.github/workflows/applesauce-cli-release.yml", args)

    def repack_arm_archive_as_gzip(self):
        """Repackage the same generated valid Mach-O fixture as a gzip tar."""
        original = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        gz = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.gz"
        with tarfile.open(original, "r:xz") as source, tarfile.open(gz, "w:gz") as output:
            for member in source:
                stream = source.extractfile(member) if member.isfile() else None
                output.addfile(member, stream)
        original.unlink()
        return gz

    def test_correct_gzip_archive_is_accepted(self):
        gzip_asset = self.repack_arm_archive_as_gzip()
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(gzip_asset.name, result.stdout)
        self.assertEqual(
            sum(call[:2] == ["release", "verify-asset"] for call in self.calls()),
            2,
        )

    def test_xz_bytes_disguised_as_gzip_are_rejected_before_provenance(self):
        xz = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        disguised = xz.with_name(xz.name.removesuffix(".tar.xz") + ".tar.gz")
        xz.rename(disguised)
        result = self.run_audit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot read tar archive", result.stderr)
        self.assertFalse(any(call[:2] == ["release", "verify-asset"]
                             for call in self.calls()))

    def test_gzip_bytes_disguised_as_xz_are_rejected_before_provenance(self):
        gzip_asset = self.repack_arm_archive_as_gzip()
        disguised = gzip_asset.with_name(
            gzip_asset.name.removesuffix(".tar.gz") + ".tar.xz"
        )
        gzip_asset.rename(disguised)
        result = self.run_audit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot read tar archive", result.stderr)
        self.assertFalse(any(call[:2] == ["release", "verify-asset"]
                             for call in self.calls()))

    def test_remote_release_tag_requires_exact_direct_commit(self):
        # Release-asset signatures alone cannot detect a tag moved after the
        # original build. Reject a new commit, annotated tag, or wrong ref.
        cases = (
            ("AUDIT_TAG_SHA", "f" * 40),
            ("AUDIT_TAG_TYPE", "tag"),
            ("AUDIT_TAG_REF", "refs/tags/applesauce-cli/v0.5.30"),
        )
        for key, invalid in cases:
            with self.subTest(key=key):
                self.env[key] = invalid
                self.log.unlink(missing_ok=True)
                result = self.run_audit()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release tag does not point directly", result.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))
                self.env.pop(key)
        self.env["AUDIT_GH_FAIL"] = "api"
        self.log.unlink(missing_ok=True)
        result = self.run_audit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gh command failed", result.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))
        self.env.pop("AUDIT_GH_FAIL")

    def test_extra_archive_filename_token_is_refused_before_provenance(self):
        for suffix in (".tar.xz", ".tar.gz"):
            with self.subTest(suffix=suffix):
                original = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
                renamed = self.downloads / (
                    "applesauce-cli-v0.5.31-unexpected-aarch64-apple-darwin" + suffix
                )
                original.rename(renamed)
                try:
                    run = self.run_audit()
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn("expected exactly one aarch64 Apple archive", run.stderr)
                    self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                         for c in self.calls()))
                finally:
                    renamed.rename(original)

    def test_wrong_cpu_fails(self):
        self.make_archive("aarch64", ARCHES["x86_64"])
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("Mach-O CPU", run.stderr)

    def test_regular_file_with_directory_style_path_is_refused(self):
        # A trailing slash on a regular file is ambiguous to tar extractors.
        # Reject before remote provenance, including on the executable itself.
        for name in ("applesauce-cli/applesauce/", "applesauce-cli/README/"):
            with self.subTest(name=name):
                self.make_archive("aarch64", ARCHES["aarch64"], name=name)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("regular file has directory-style path", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

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

    def test_rejects_oversized_legacy_macos_version_command(self):
        # LC_VERSION_MIN_MACOSX has a fixed 16-byte structure; an aligned
        # trailing payload must not be silently accepted as valid metadata.
        self.make_archive("aarch64", ARCHES["aarch64"],
                          platform="legacy", legacy_extra_bytes=8)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("malformed macOS version command size", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_rejects_misaligned_unknown_macho_load_command(self):
        # A malformed unknown LC_* used to pass structural validation because
        # the auditor checked only that the command ended inside sizeofcmds.
        for length in (9, 15, 17):
            with self.subTest(length=length):
                self.make_archive("aarch64", ARCHES["aarch64"],
                                  unknown_command_size=length, entry_offset=128)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("invalid Mach-O load command size or alignment", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_accepts_aligned_unknown_macho_load_command(self):
        # Future LC_* types must not be rejected merely for being unfamiliar.
        self.make_archive("aarch64", ARCHES["aarch64"],
                          unknown_command_size=16)
        run = self.run_audit()
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_rejects_malformed_macho_build_tool_count(self):
        # LC_BUILD_VERSION declares an array of 8-byte build_tool_version
        # records. A nonzero ntools with only the 24-byte header is malformed.
        self.make_archive("aarch64", ARCHES["aarch64"], build_tool_count=1)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("inconsistent Mach-O build tool table", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_rejects_macho_without_entry_command_before_remote_verification(self):
        # CPU, filetype and macOS platform are insufficient to certify a
        # runnable binary if the entry command was omitted altogether.
        self.make_archive("aarch64", ARCHES["aarch64"], entry_offset=None)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("missing Mach-O LC_MAIN entry point", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_rejects_out_of_bounds_macho_entrypoint(self):
        self.make_archive("aarch64", ARCHES["aarch64"], entry_offset=10_000)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("entry offset outside executable", run.stderr)

    def test_rejects_entrypoint_overlapping_macho_load_commands(self):
        # Header (32) + LC_BUILD_VERSION (24) + LC_MAIN (24) = 80 bytes.
        for entry_offset in (0, 32, 64, 79):
            with self.subTest(entry_offset=entry_offset):
                self.make_archive("aarch64", ARCHES["aarch64"],
                                  entry_offset=entry_offset)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("entry offset overlaps load commands", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_accepts_in_bounds_macho_entrypoint_and_hashes_full_binary(self):
        self.make_archive("aarch64", ARCHES["aarch64"], entry_offset=96)
        run = self.run_audit()
        self.assertEqual(run.returncode, 0, run.stderr)
        asset = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        with tarfile.open(asset, "r:xz") as tar:
            executable = tar.extractfile("applesauce-cli/applesauce").read()
        self.assertIn(hashlib.sha256(executable).hexdigest(), run.stdout)

    def test_duplicate_macho_main_is_refused_before_provenance(self):
        self.make_archive("aarch64", ARCHES["aarch64"],
                          # With two LC_MAIN commands, the header and command table occupy
                          # 32 + 24 + 24 + 24 = 104 bytes. A valid offset
                          # reaches the duplicate-command guard itself.
                          entry_offset=104, duplicate_entry=True)
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("duplicate Mach-O LC_MAIN", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_nonzero_reserved_macho_header_is_refused_before_provenance(self):
        for reserved in (1, 0xffffffff):
            with self.subTest(reserved=reserved):
                self.make_archive("aarch64", ARCHES["aarch64"], reserved=reserved)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("nonzero Mach-O reserved header", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_dynamic_library_header_is_refused(self):
        self.make_archive("x86_64", ARCHES["x86_64"], filetype=6)
        self.assertIn("expected executable", self.run_audit().stderr)

    def test_symlinked_download_is_refused(self):
        target = self.downloads / "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        real = self.path / "outside-archive.tar.xz"
        target.rename(real)
        target.symlink_to(real)
        self.assertIn("exactly one aarch64", self.run_audit().stderr)

    def test_wrong_release_version_archive_name_is_refused_before_provenance(self):
        # An attested archive from another version must not be accepted merely
        # because its filename starts with "applesauce" and ends in the CPU suffix.
        original = self.downloads / (
            "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        )
        original.rename(
            self.downloads / "applesauce-cli-v0.5.30-aarch64-apple-darwin.tar.xz"
        )
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("expected exactly one aarch64 Apple archive", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

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

    def test_writable_nonbinary_regular_file_is_refused_before_provenance(self):
        for mode in (0o664, 0o646, 0o666):
            with self.subTest(mode=oct(mode)):
                path = self.downloads / (
                    "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
                )
                with tarfile.open(path, "w:xz") as tar:
                    member = tarfile.TarInfo("applesauce-cli/README")
                    member.mode = mode
                    data = b"generated fixture"
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("writable archive regular file", run.stderr)
                self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                                     for c in self.calls()))

    def test_directory_payload_is_refused_before_provenance(self):
        path = self.downloads / (
            "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
        )
        with tarfile.open(path, "w:xz") as tar:
            directory = tarfile.TarInfo("applesauce-cli/docs")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.size = 1
            tar.addfile(directory, io.BytesIO(b"x"))
        run = self.run_audit()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("nonempty archive directory entry", run.stderr)
        self.assertFalse(any(c[:2] == ["release", "verify-asset"]
                             for c in self.calls()))

    def test_writable_archive_directory_is_refused_before_provenance(self):
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                path = self.downloads / (
                    "applesauce-cli-v0.5.31-aarch64-apple-darwin.tar.xz"
                )
                with tarfile.open(path, "w:xz") as tar:
                    directory = tarfile.TarInfo("applesauce-cli/docs")
                    directory.type = tarfile.DIRTYPE
                    directory.mode = mode
                    tar.addfile(directory)
                self.log.unlink(missing_ok=True)
                run = self.run_audit()
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("writable archive directory", run.stderr)
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
                # The earlier universal regular-file permission gate now
                # rejects this archive before executable-specific checks.
                self.assertIn("writable archive regular file", run.stderr)
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
