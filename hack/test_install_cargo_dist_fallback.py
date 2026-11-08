"""Offline regression tests for the immutable, SHA-pinned cargo-dist asset fallback.

Tests use generated tar.xz files and a synthetic curl executable. No release
asset or remote host is contacted, and no real cargo installation is changed.
"""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("install-cargo-dist.sh")
PINNED_ASSET_SHA256 = "4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293"


class PinnedAssetFallbackTests(unittest.TestCase):
    def run_asset(
        self,
        *,
        binary=b"#!/bin/sh\nprintf 'dist 0.33.0\\n'\n",
        entries=None,
        correct_digest=True,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            bindir = root / "bin"
            bindir.mkdir()
            archive_path = root / "generated-asset.tar.xz"
            if entries is None:
                entries = [("cargo-dist-linux/dist", binary, "file")]
            with tarfile.open(archive_path, "w:xz") as archive:
                for name, data, kind in entries:
                    info = tarfile.TarInfo(name)
                    if kind == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "other-file"
                        archive.addfile(info)
                    else:
                        info.mode = 0o755
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            script_path = root / "installer.sh"
            source = SCRIPT.read_text()
            self.assertIn(PINNED_ASSET_SHA256, source)
            if correct_digest:
                source = source.replace(PINNED_ASSET_SHA256, digest)
            script_path.write_text(source)

            mock_curl = bindir / "curl"
            mock_curl.write_text(
                "#!/bin/sh\n"
                "destination=''\n"
                "api=0\n"
                "while [ $# -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    --output) shift; destination=$1 ;;\n"
                "    *api.github.com/repos/axodotdev/cargo-dist/releases/assets/*) api=1 ;;\n"
                "  esac\n"
                "  shift\n"
                "done\n"
                "if [ \"$api\" != 1 ]; then exit 22; fi\n"
                "cp \"$MOCK_ARCHIVE\" \"$destination\"\n"
            )
            mock_curl.chmod(0o700)
            env = os.environ.copy()
            env.update(
                HOME=str(home),
                RUNNER_TEMP=str(root),
                PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                MOCK_ARCHIVE=str(archive_path),
            )
            result = subprocess.run(
                ["bash", str(script_path)], env=env, text=True,
                capture_output=True, timeout=20, check=False,
            )
            installed = home / ".cargo" / "bin" / "dist"
            installed_bytes = installed.read_bytes() if installed.exists() else None
            self.assertEqual(list(root.glob("cargo-dist-asset.*")), [])
            self.assertEqual(list(root.glob("cargo-dist-binary.*")), [])
            self.assertEqual(list(root.glob("cargo-dist-installer.*")), [])
            return result, installed_bytes

    def test_primary_504_recovers_using_verified_api_asset(self):
        result, installed = self.run_asset()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHA-verified pinned cargo-dist fallback", result.stdout)
        self.assertIn(b"dist 0.33.0", installed)

    def test_tampered_asset_digest_fails_without_installation(self):
        result, installed = self.run_asset(correct_digest=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertIsNone(installed)

    def test_wrong_binary_version_fails_before_installation(self):
        result, installed = self.run_asset(
            binary=b"#!/bin/sh\nprintf 'dist 0.33.1\\n'\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected or unavailable version", result.stderr)
        self.assertIsNone(installed)

    def test_duplicate_binary_entries_are_rejected(self):
        result, installed = self.run_asset(entries=[
            ("first/dist", b"#!/bin/sh\nexit 0\n", "file"),
            ("second/dist", b"#!/bin/sh\nexit 0\n", "file"),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unique bounded regular dist executable", result.stderr)
        self.assertIsNone(installed)

    def test_symlink_entry_is_rejected(self):
        result, installed = self.run_asset(entries=[
            ("package/dist", b"", "symlink"),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unique bounded regular dist executable", result.stderr)
        self.assertIsNone(installed)


if __name__ == "__main__":
    unittest.main()
