#!/usr/bin/env python3
"""Validate identity and provisioning of the signed FSKit app/extension.

The host script verifies the code signature and CMS envelope before calling
this helper. This preflight does not establish that a volume was mounted.
"""
import datetime
import hashlib
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
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
    require(expiry > current,
            f"{name}: embedded provisioning profile expired on {expiry.isoformat()}")

    # A wildcard provisioning profile may authorize several apps. A signed
    # application identifier, when present, must name this exact bundle.
    for key in ("com.apple.application-identifier", "application-identifier"):
        signed_id = signed.get(key)
        if signed_id is not None:
            require(signed_id == f"{team}.{bundle_id}",
                    f"{name}: signed {key} does not match the bundle identity")
        allowed_id = authorized.get(key)
        if allowed_id is not None:
            prefix = team + "."
            require(isinstance(allowed_id, str) and allowed_id.startswith(prefix),
                    f"{name}: profile {key} has a different team prefix")
            pattern = allowed_id[len(prefix):]
            match = pattern == bundle_id or pattern == "*" or (
                pattern.endswith(".*") and bundle_id.startswith(pattern[:-1]))
            require(match,
                    f"{name}: provisioning profile does not authorize {bundle_id}")
    signed_team = signed.get("com.apple.developer.team-identifier")
    if signed_team is not None:
        require(signed_team == team,
                f"{name}: signed developer team entitlement is inconsistent")
    print(f"{name}: restricted FSKit grant, signing team, bundle ID and unexpired profile checked")


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
                "com.apple.application-identifier": self.team + ".*",
            },
        }

    def verify(self):
        check(self.signed, self.profile, self.entitlement, "host",
              self.team, self.bundle_id,
              now=datetime.datetime(2026, 11, 5, tzinfo=datetime.timezone.utc))

    def test_valid_wildcard(self):
        self.verify()

    def test_exact_bundle_id(self):
        self.profile["Entitlements"]["com.apple.application-identifier"] = (
            self.team + "." + self.bundle_id)
        self.verify()

    def test_optional_application_id(self):
        self.signed.pop("com.apple.application-identifier")
        self.profile["Entitlements"].pop("com.apple.application-identifier")
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
