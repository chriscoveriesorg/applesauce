"""Offline, disposable negative controls for the version-pinned dist bootstrap."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("install-cargo-dist.sh")


class InstallCargoDistTests(unittest.TestCase):
    def run_installer(self, *, fail_download=False, fail_installs=0, version="0.33.0"):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            bindir = directory / "bin"
            bindir.mkdir()
            attempts = directory / "attempts"
            attempts.write_text("0")
            installer = directory / "mock-installer.sh"
            installer.write_text(
                "#!/bin/sh\n"
                "n=$(cat \"$MOCK_ATTEMPTS\")\n"
                "n=$((n+1))\n"
                "printf '%s' \"$n\" > \"$MOCK_ATTEMPTS\"\n"
                "if [ \"$n\" -le \"$MOCK_FAIL_INSTALLS\" ]; then exit 22; fi\n"
                "exit 0\n"
            )
            mock_curl = bindir / "curl"
            mock_curl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" > \"$MOCK_CURL_ARGS\"\n"
                "if [ \"$MOCK_FAIL_DOWNLOAD\" = 1 ]; then exit 22; fi\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then\n"
                "    shift\n"
                "    cp \"$MOCK_INSTALLER\" \"$1\"\n"
                "    exit $?\n"
                "  fi\n"
                "  shift\n"
                "done\n"
                "exit 2\n"
            )
            mock_dist = bindir / "dist"
            mock_dist.write_text("#!/bin/sh\nprintf 'dist %s\\n' \"$MOCK_DIST_VERSION\"\n")
            mock_sleep = bindir / "sleep"
            mock_sleep.write_text("#!/bin/sh\nexit 0\n")
            for path in [mock_curl, mock_dist, mock_sleep]:
                path.chmod(0o700)
            curl_args = directory / "curl-args"
            env = os.environ.copy()
            env.update(
                PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                RUNNER_TEMP=str(directory),
                MOCK_ATTEMPTS=str(attempts),
                MOCK_FAIL_INSTALLS=str(fail_installs),
                MOCK_FAIL_DOWNLOAD="1" if fail_download else "0",
                MOCK_INSTALLER=str(installer),
                MOCK_CURL_ARGS=str(curl_args),
                MOCK_DIST_VERSION=version,
            )
            process = subprocess.run(
                ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=15,
                check=False,
            )
            result = (process, int(attempts.read_text()), curl_args.read_text())
            self.assertEqual(list(directory.glob("cargo-dist-installer.*")), [])
            return result

    def test_bounded_retry_after_transient_installer_transfer_failure(self):
        process, attempts, curl = self.run_installer(fail_installs=2)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(attempts, 3)
        self.assertIn("dist 0.33.0", process.stdout)
        self.assertIn("--retry-all-errors", curl)
        self.assertIn("cargo-dist/releases/download/v0.33.0/", curl)

    def test_exhausted_retries_fail_closed(self):
        process, attempts, _ = self.run_installer(fail_installs=99)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(attempts, 3)
        self.assertIn("after 3 attempts", process.stderr)

    def test_download_error_never_runs_installer(self):
        process, attempts, _ = self.run_installer(fail_download=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(attempts, 0)

    def test_wrong_version_fails_without_retry(self):
        process, attempts, _ = self.run_installer(version="0.33.1")
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(attempts, 1)
        self.assertIn("unexpected version", process.stderr)


if __name__ == "__main__":
    unittest.main()
