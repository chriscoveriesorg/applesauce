#!/usr/bin/env python3
"""Validate identity and provisioning of the signed FSKit app/extension.

The host script verifies the code signature and CMS envelope before calling
this helper. This preflight does not establish that a volume was mounted.
"""
import contextlib
import datetime
import hashlib
import io
from pathlib import Path
import plistlib
import re
import ssl
import subprocess
import sys
import unittest


class SigningProfileError(ValueError):
    pass


def select_identity(identities, subjects, team):
    """Select only a valid Apple Development identity with a matching OU.

    subjects maps certificate SHA-1 fingerprints to OpenSSL subject text.
    """
    for fingerprint, name in re.findall(
            r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(Apple Development:[^"\r\n]+)"',
            identities, re.MULTILINE):
        subject = subjects.get(fingerprint.upper(), "")
        ous = re.findall(r'^\s*OU\s*=\s*([^\r\n]+?)\s*$', subject, re.MULTILINE)
        if team in ous:
            return name
    return None


def certificate_subjects(certificates):
    """Extract subjects and fingerprint the actual PEM bytes, not labels."""
    subjects = {}
    for pem in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                          certificates, re.DOTALL):
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
            fingerprint = hashlib.sha1(der).hexdigest().upper()
            result = subprocess.run(
                ["/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "sep_multiline"],
                input=pem, text=True, capture_output=True, check=True)
            subjects[fingerprint] = result.stdout
        except (ValueError, subprocess.CalledProcessError):
            continue
    return subjects


def preflight_identity(team):
    try:
        identities = subprocess.run(
            ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
            text=True, capture_output=True, check=True).stdout
        certificates = subprocess.run(
            ["/usr/bin/security", "find-certificate", "-a", "-Z", "-c", "Apple Development", "-p"],
            text=True, capture_output=True, check=True).stdout
        identity = select_identity(identities, certificate_subjects(certificates), team)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"ASCF signing preflight: cannot inspect local signing certificates: {error}",
              file=sys.stderr)
        return 1
    if not identity:
        return 1
    print(identity)
    return 0


def require(condition, message):
    if not condition:
        raise SigningProfileError(message)


def check(signed, profile, entitlement, name, team, bundle_id, now=None):
    require(signed.get(entitlement) is True,
            f"{name}: signed binary lacks restricted {entitlement}")
    authorized = profile.get("Entitlements", {})
    require(isinstance(authorized, dict) and authorized.get(entitlement) is True,
            f"{name}: provisioning profile does not grant {entitlement}")
    require(isinstance(team, str) and len(team) == 10 and team.isalnum(),
            f"{name}: no valid codesign TeamIdentifier")
    profile_teams = profile.get("TeamIdentifier")
    require(isinstance(profile_teams, list) and team in profile_teams,
            f"{name}: provisioning TeamIdentifier differs from code signature")

    expiry = profile.get("ExpirationDate")
    require(isinstance(expiry, datetime.datetime),
            f"{name}: provisioning profile has no expiration date")
    current = now or datetime.datetime.now(datetime.timezone.utc)
    # A development identity cannot sign an iOS/tvOS-only profile for a
    # macOS FSKit extension. Xcode's automatic signing may fail much later
    # without this explicit, read-only local diagnostic. Older profile
    # formats may omit Platform, so validate it whenever it is provided.
    if "Platform" in profile:
        platforms = profile["Platform"]
        require(isinstance(platforms, list)
                and all(isinstance(platform, str) for platform in platforms)
                and any(platform.upper() in ("OSX", "MACOS", "MACOSX")
                        for platform in platforms),
                f"{name}: provisioning profile is not for macOS")
    created = profile.get("CreationDate")
    if created is not None:
        require(isinstance(created, datetime.datetime),
                f"{name}: invalid provisioning profile creation date")
        if created.tzinfo is None:
            created = created.replace(tzinfo=datetime.timezone.utc)
        require(created <= current,
                f"{name}: provisioning profile is not yet valid")
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
    require(expiry > current,
            f"{name}: embedded provisioning profile expired on {expiry.isoformat()}")

    # FSKit's restricted grant must belong to the signed host/extension.
    # macOS code signatures may omit application-identifier, but the embedded
    # provisioning profile must bind its restricted grant to the selected
    # bundle. Otherwise an unrelated valid profile could be accepted.
    identity_keys = ("com.apple.application-identifier", "application-identifier")
    require(any(authorized.get(key) is not None for key in identity_keys),
            f"{name}: provisioning profile lacks an application identifier")
    # Check every supplied alias. Conflicting aliases are not interchangeable.
    for key in identity_keys:
        signed_id = signed.get(key)
        if signed_id is not None:
            require(signed_id == f"{team}.{bundle_id}",
                    f"{name}: signed {key} does not match the bundle identity")
        allowed_id = authorized.get(key)
        if allowed_id is not None:
            # These are restricted filesystem entitlements. For the signed
            # acceptance gate demand an explicit provisioned App ID, rather
            # than treating a wildcard profile as proof of the two approved
            # FSKit capabilities. This also rejects partial wildcard aliases.
            require(allowed_id == f"{team}.{bundle_id}",
                    f"{name}: provisioning profile does not authorize the "
                    f"explicit FSKit App ID {bundle_id}")
    signed_team = signed.get("com.apple.developer.team-identifier")
    if signed_team is not None:
        require(signed_team == team,
                f"{name}: signed developer team entitlement is inconsistent")
    print(f"{name}: restricted FSKit grant, signing team, bundle ID and unexpired profile checked")



# Automatic Xcode signing does not establish that the restricted FSKit
# capabilities have been granted. Check both installed profile grants before
# spending time compiling Rust and the host. This is only a pre-build gate;
# signed bundle entitlements and real mounted acceptance are checked later.
FSKIT_TARGETS = (
    ("host", "org.chriscoveries.applesauce.ascfhost",
     "com.apple.developer.fskit.mount"),
    ("extension", "org.chriscoveries.applesauce.ascfhost.ascfextension",
     "com.apple.developer.fskit.fsmodule"),
)


def covered_targets(profiles, team, now=None):
    """Return targets authorized by unexpired, team-matched local profiles."""
    covered = set()
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        allowed = profile.get("Entitlements", {})
        if not isinstance(allowed, dict):
            continue
        # A usable provisioning profile must identify which app it grants.
        # The signed-binary validation separately authenticates its actual ID.
        if not any(isinstance(allowed.get(key), str)
                   for key in ("com.apple.application-identifier",
                               "application-identifier")):
            continue
        for name, bundle_id, entitlement in FSKIT_TARGETS:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    check({entitlement: True,
                           "com.apple.application-identifier": team + "." + bundle_id},
                          profile, entitlement, name, team, bundle_id, now=now)
            except SigningProfileError:
                continue
            covered.add(name)
    return covered


def local_profile_paths(home):
    """Search both legacy and newer Xcode provisioning-profile locations."""
    roots = (
        home / "Library/MobileDevice/Provisioning Profiles",
        home / "Library/Developer/Xcode/UserData/Provisioning Profiles",
    )
    found = []
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for suffix in ("*.mobileprovision", "*.provisionprofile"):
            for path in sorted(root.glob(suffix)):
                # Local profile directories are input, not a trusted source
                # of executable code. Refuse links, empty files and enormous
                # CMS envelopes before security(1) decodes them.
                try:
                    if (not path.is_symlink() and path.is_file()
                            and 0 < path.stat().st_size <= 8 * 1024 * 1024):
                        found.append(path)
                except OSError:
                    continue
    return found


def preflight_profiles(team, home=None, decode=None):
    """Fail early with a precise missing grant; never print private profile data.

    Xcode-managed signing may download profiles during an interactive setup.
    If so, provision them in Xcode first, then rerun this read-only preflight.
    """
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        print("ASCF profile preflight: invalid developer team ID", file=sys.stderr)
        return 1
    if home is None:
        home = Path.home()
    if decode is None:
        def decode(path):
            return subprocess.run(
                ["/usr/bin/security", "cms", "-D", "-i", str(path)],
                check=True, capture_output=True, timeout=15).stdout
    decoded = []
    paths = local_profile_paths(home)
    for path in paths:
        try:
            # A malformed or unrelated local profile must not prevent a valid
            # profile later in the scan from satisfying either FSKit target.
            profile = plistlib.loads(decode(path))
        except (OSError, ValueError, plistlib.InvalidFileException,
                subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        decoded.append(profile)
    covered = covered_targets(decoded, team)
    missing = sorted({target[0] for target in FSKIT_TARGETS} - covered)
    if missing:
        for name in missing:
            bundle_id = next(target[1] for target in FSKIT_TARGETS if target[0] == name)
            entitlement = next(target[2] for target in FSKIT_TARGETS if target[0] == name)
            print(f"ASCF profile preflight: missing unexpired {name} provisioning "
                  f"profile for {bundle_id} granting {entitlement}", file=sys.stderr)
        print("Provision both restricted FSKit app IDs in Xcode and install "
              "their profiles before signed-build. This checks local grants, "
              "not Apple approval or a successful mount.", file=sys.stderr)
        return 1
    print("FSKit local profile preflight: both restricted app/extension "
          "grants found for the selected team; signed-build will verify "
          "the actual code signatures and embedded profiles.")
    return 0


class ProfileCoverageTests(unittest.TestCase):
    team = "ABCDEF1234"

    def profile(self, target, wildcard=False):
        name, bundle, entitlement = target
        return {
            "TeamIdentifier": [self.team],
            "ExpirationDate": datetime.datetime(2028, 1, 1),
            "Entitlements": {
                entitlement: True,
                "com.apple.application-identifier": self.team + "." +
                    ("*" if wildcard else bundle),
            },
        }

    def test_explicit_iphone_profile_never_satisfies_mac_fskit(self):
        host, extension = FSKIT_TARGETS
        iphone = self.profile(host)
        iphone["Platform"] = ["iOS"]
        mac = self.profile(extension)
        mac["Platform"] = ["OSX"]
        now = datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)
        self.assertEqual(covered_targets([iphone, mac], self.team, now),
                         {"extension"})
        for invalid_platform in ([], ["iOS", "tvOS"], "OSX", [42]):
            with self.subTest(platform=invalid_platform):
                iphone["Platform"] = invalid_platform
                self.assertEqual(covered_targets([iphone], self.team, now), set())
        iphone["Platform"] = ["OSX"]
        self.assertEqual(covered_targets([iphone, mac], self.team, now),
                         {"host", "extension"})

    def test_future_profile_creation_date_cannot_satisfy_preflight(self):
        host = self.profile(FSKIT_TARGETS[0])
        now = datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)
        host["CreationDate"] = datetime.datetime(2027, 2, 1)
        self.assertEqual(covered_targets([host], self.team, now), set())
        host["CreationDate"] = datetime.datetime(2026, 11, 1)
        self.assertEqual(covered_targets([host], self.team, now), {"host"})

    def test_scan_refuses_oversize_and_empty_local_profiles(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            folder = home / "Library/MobileDevice/Provisioning Profiles"
            folder.mkdir(parents=True)
            (folder / "empty.mobileprovision").write_bytes(b"")
            with (folder / "oversize.provisionprofile").open("wb") as fd:
                fd.truncate(8 * 1024 * 1024 + 1)
            good = folder / "host.mobileprovision"
            good.write_bytes(b"small CMS fixture")
            self.assertEqual(local_profile_paths(home), [good])

    def test_both_profiles_are_required(self):
        host, extension = FSKIT_TARGETS
        self.assertEqual(covered_targets([self.profile(host)],
                         self.team, datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)),
                         {"host"})
        self.assertEqual(covered_targets([self.profile(host),
                                         self.profile(extension)], self.team,
                         datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)), {"host", "extension"})

    def test_wrong_team_expiry_and_wrong_app_are_refused(self):
        host = FSKIT_TARGETS[0]
        for field in ("team", "expiry", "app", "grant"):
            with self.subTest(field=field):
                profile = self.profile(host)
                if field == "team":
                    profile["TeamIdentifier"] = ["OTHER12345"]
                elif field == "expiry":
                    profile["ExpirationDate"] = datetime.datetime(2020, 1, 1)
                elif field == "app":
                    profile["Entitlements"]["com.apple.application-identifier"] = (
                        self.team + ".unrelated.app")
                else:
                    profile["Entitlements"][host[2]] = False
                self.assertEqual(covered_targets([profile], self.team,
                                 datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)), set())

    def test_profile_without_application_identity_is_refused(self):
        profile = self.profile(FSKIT_TARGETS[0])
        del profile["Entitlements"]["com.apple.application-identifier"]
        self.assertFalse(covered_targets([profile], self.team))

    def test_wildcard_profiles_do_not_satisfy_restricted_targets(self):
        now = datetime.datetime(2026, 11, 6, tzinfo=datetime.timezone.utc)
        host, extension = FSKIT_TARGETS
        wildcards = [self.profile(host, wildcard=True),
                     self.profile(extension, wildcard=True)]
        self.assertEqual(covered_targets(wildcards, self.team, now), set())
        # An unrelated wildcard profile must not fill the absent extension
        # grant even when a valid explicit host profile is installed.
        self.assertEqual(covered_targets([self.profile(host), wildcards[1]],
                                          self.team, now), {"host"})

    def test_corrupt_files_do_not_mask_valid_grants(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            folder = home / "Library/MobileDevice/Provisioning Profiles"
            folder.mkdir(parents=True)
            for name in ("bad", "host", "extension"):
                (folder / (name + ".mobileprovision")).write_bytes(b"dummy")
            payloads = {
                "bad": b"not a plist",
                "host": plistlib.dumps(self.profile(FSKIT_TARGETS[0])),
                "extension": plistlib.dumps(self.profile(FSKIT_TARGETS[1])),
            }
            decoder = lambda path: payloads[path.stem]
            self.assertEqual(preflight_profiles(self.team, home, decoder), 0)
            (folder / "extension.mobileprovision").unlink()
            self.assertEqual(preflight_profiles(self.team, home, decoder), 1)

    def test_symlinked_profile_is_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            folder = home / "Library/Developer/Xcode/UserData/Provisioning Profiles"
            folder.mkdir(parents=True)
            elsewhere = home / "elsewhere.mobileprovision"
            elsewhere.write_bytes(b"outside")
            (folder / "fake.mobileprovision").symlink_to(elsewhere)
            self.assertEqual(local_profile_paths(home), [])
            regular = folder / "valid.provisionprofile"
            regular.write_bytes(b"macOS-style profile")
            self.assertEqual(local_profile_paths(home), [regular])


class SigningProfileTests(unittest.TestCase):
    team = "ABCDEF1234"
    bundle_id = "org.chriscoveries.applesauce.ascfhost"
    entitlement = "com.apple.developer.fskit.mount"

    def setUp(self):
        self.signed = {
            self.entitlement: True,
            "com.apple.application-identifier": self.team + "." + self.bundle_id,
        }
        self.profile = {
            "TeamIdentifier": [self.team],
            "ExpirationDate": datetime.datetime(2028, 1, 1),
            "Entitlements": {
                self.entitlement: True,
                "com.apple.application-identifier": self.team + "." + self.bundle_id,
            },
        }

    def verify(self):
        check(self.signed, self.profile, self.entitlement, "host",
              self.team, self.bundle_id,
              now=datetime.datetime(2026, 11, 5, tzinfo=datetime.timezone.utc))

    def test_restricted_fsKit_grant_requires_explicit_app_id(self):
        for wildcard in ("*", "org.chriscoveries.*"):
            with self.subTest(wildcard=wildcard):
                self.profile["Entitlements"]["com.apple.application-identifier"] = (
                    self.team + "." + wildcard)
                with self.assertRaisesRegex(SigningProfileError, "explicit FSKit App ID"):
                    self.verify()
        self.profile["Entitlements"]["com.apple.application-identifier"] = (
            self.team + "." + self.bundle_id)
        self.verify()

    def test_exact_bundle_id(self):
        self.profile["Entitlements"]["com.apple.application-identifier"] = (
            self.team + "." + self.bundle_id)
        self.verify()

    def test_signed_application_id_may_be_absent(self):
        # A macOS binary may omit this entitlement. The profile still binds
        # its restricted FSKit grant to the exact installed bundle.
        self.signed.pop("com.apple.application-identifier")
        self.verify()

    def test_profile_application_id_is_mandatory(self):
        self.profile["Entitlements"].pop("com.apple.application-identifier")
        with self.assertRaisesRegex(SigningProfileError, "lacks an application identifier"):
            self.verify()

    def test_null_application_identifier_is_rejected(self):
        self.profile["Entitlements"]["com.apple.application-identifier"] = None
        with self.assertRaisesRegex(SigningProfileError, "lacks an application identifier"):
            self.verify()

    def test_conflicting_application_id_aliases_are_rejected(self):
        # Neither a second, contradictory provisioned ID nor an incorrect
        # signed alias can override the otherwise valid primary identity.
        self.profile["Entitlements"]["application-identifier"] = (
            self.team + ".different.app")
        with self.assertRaisesRegex(SigningProfileError, "does not authorize"):
            self.verify()
        self.profile["Entitlements"].pop("application-identifier")
        self.signed["application-identifier"] = self.team + ".different.app"
        with self.assertRaisesRegex(SigningProfileError, "does not match"):
            self.verify()

    def test_wrong_team(self):
        self.profile["TeamIdentifier"] = ["OTHER12345"]
        with self.assertRaisesRegex(SigningProfileError, "TeamIdentifier"):
            self.verify()

    def test_wrong_bundle(self):
        self.profile["Entitlements"]["com.apple.application-identifier"] = (
            self.team + ".com.other.*")
        with self.assertRaisesRegex(SigningProfileError, "does not authorize"):
            self.verify()

    def test_expired(self):
        self.profile["ExpirationDate"] = datetime.datetime(2026, 1, 1)
        with self.assertRaisesRegex(SigningProfileError, "expired"):
            self.verify()

    def test_missing_grant(self):
        self.profile["Entitlements"][self.entitlement] = False
        with self.assertRaisesRegex(SigningProfileError, "does not grant"):
            self.verify()


class IdentitySelectionTests(unittest.TestCase):
    first = "A" * 40
    second = "B" * 40
    name = "Apple Development: Example Person (PERSON1234)"
    team = "TEAM123456"

    def line(self, fingerprint, name=None):
        return f'  1) {fingerprint} "{name or self.name}"\n'

    def subject(self, team):
        return f"subject=\n    CN={self.name}\n    OU={team}\n"

    def test_personal_id_differs_from_team(self):
        self.assertEqual(select_identity(self.line(self.first),
                                        {self.first: self.subject(self.team)}, self.team), self.name)

    def test_name_suffix_does_not_override_wrong_ou(self):
        name = f"Apple Development: Example Person ({self.team})"
        self.assertIsNone(select_identity(self.line(self.first, name),
                                         {self.first: self.subject("OTHER12345")}, self.team))

    def test_certificate_absent_from_valid_identity_list(self):
        self.assertIsNone(select_identity("  0 valid identities found\n",
                                         {self.first: self.subject(self.team)}, self.team))

    def test_multiple_identities_select_matching_ou(self):
        other = "Apple Development: Other Person (OTHER12345)"
        identities = self.line(self.first, other) + self.line(self.second)
        subjects = {self.first: self.subject("OTHER12345"),
                    self.second: self.subject(self.team)}
        self.assertEqual(select_identity(identities, subjects, self.team), self.name)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if len(sys.argv) == 3 and sys.argv[1] == "--preflight-identity":
        return preflight_identity(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == "--preflight-profiles":
        return preflight_profiles(sys.argv[2])
    if len(sys.argv) != 7:
        sys.exit("usage: signing_profile.py ENTITLEMENTS.plist PROFILE.plist FSKit_KEY NAME TEAM_ID BUNDLE_ID")
    try:
        with open(sys.argv[1], "rb") as fd:
            signed = plistlib.load(fd)
        with open(sys.argv[2], "rb") as fd:
            profile = plistlib.load(fd)
        check(signed, profile, *sys.argv[3:])
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        print(f"ASCF signing profile invalid: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
