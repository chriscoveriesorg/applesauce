#!/usr/bin/env python3
"""Descriptor-anchored, fail-closed publication of derived benchmark CSVs.

The benchmark workflow uploads artifacts even after a failed step. Remove only
the stale output entry before parsing evidence. A moved/symlinked destination
directory must never redirect cleanup or publication to an input artifact.
"""
import csv
import os
from pathlib import Path
import secrets
import stat
import sys


class SafeCsvOutput:
    def __init__(self, destination: Path, sources=()):
        self.destination = Path(destination)
        self.sources = tuple(Path(source) for source in sources)
        self.directory = None
        self.opened_identity = None

    def __enter__(self):
        output = self.destination
        if output.name in ("", ".", ".."):
            raise ValueError("invalid benchmark output filename")
        if output.parent.is_symlink():
            raise ValueError("benchmark output directory must not be a symlink")
        parent = output.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError("benchmark output parent must be a directory")
        for source in self.sources:
            if output.resolve(strict=False) == source.resolve(strict=False):
                raise ValueError("benchmark output must differ from source evidence")
            # A missing source must not prevent stale derived-evidence cleanup.
            # The subsequent manifest/summary validation will still fail.
            try:
                aliased = output.exists() and os.path.samefile(output, source)
            except FileNotFoundError:
                aliased = False
            if aliased:
                raise ValueError("benchmark output must differ from source evidence")
        required = ("O_DIRECTORY", "O_NOFOLLOW")
        if not all(hasattr(os, flag) for flag in required):
            raise OSError("safe benchmark output needs O_DIRECTORY and O_NOFOLLOW")
        # Capture the expected inode *before* open, including races where
        # an attacker swaps a real directory for another real directory.
        known = os.stat(parent)
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (known.st_dev, known.st_ino):
                raise ValueError("benchmark output directory changed during open")
            # A private mode is insufficient when this process does not own
            # the directory (for example, access granted through an ACL).
            # The owner can replace entries or relax permissions at any time.
            if opened.st_uid != os.geteuid():
                raise ValueError("benchmark output directory must be owned by current user")
            # Publication cleanup assumes exclusive control of this directory.
            # Refuse directories writable by other users: pathname identity
            # checks alone cannot prevent concurrent entry substitution.
            # Same-UID cooperating processes must still serialize writes.
            if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError(
                    "benchmark output directory must not be group/world writable"
                )
            # The pathname can be swapped after opening the descriptor but
            # before stale-output cleanup. Refuse to delete from a displaced
            # directory, even though the descriptor itself remains valid.
            visible = os.stat(output.parent, follow_symlinks=False)
            if (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("benchmark output directory changed during open")
            # The output may be a hardlink. Verify the actual directory entry
            # after opening its parent, and before unlinking old evidence.
            try:
                current = os.stat(output.name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None:
                for source in self.sources:
                    try:
                        source_stat = os.stat(source, follow_symlinks=False)
                    except FileNotFoundError:
                        # Missing evidence must not prevent stale derived-output
                        # cleanup; the subsequent evidence validation will fail.
                        continue
                    if (current.st_dev, current.st_ino) == (
                        source_stat.st_dev, source_stat.st_ino
                    ):
                        raise ValueError("benchmark output must differ from source evidence")
            try:
                os.unlink(output.name, dir_fd=fd)
            except FileNotFoundError:
                pass
            else:
                # The workflow uploads artifacts even when validation fails.
                # Persist stale-entry removal before reading fresh evidence.
                os.fsync(fd)
            self.directory = fd
            self.opened_identity = (opened.st_dev, opened.st_ino)
            return self
        except BaseException:
            os.close(fd)
            raise

    def _cleanup_published(self, identity):
        # Never unlink a pathname after checking its identity: another
        # same-UID process can substitute the entry between stat and unlink.
        # Instead invalidate only the inode held by an open descriptor.
        # A zero-length CSV is not valid benchmark evidence.
        try:
            fd = os.open(
                self.destination.name, os.O_WRONLY | os.O_NOFOLLOW,
                dir_fd=self.directory,
            )
        except OSError:
            return  # Preserve the original publication failure.
        try:
            opened = os.fstat(fd)
            if (
                (opened.st_dev, opened.st_ino) != identity
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                # Do not truncate a published inode shared with another
                # pathname. Preserve the original publication error instead.
                # This is best-effort, not a defense against a concurrent
                # same-UID process creating a hardlink after this check.
                return
            os.ftruncate(fd, 0)
            os.fsync(fd)
            os.fsync(self.directory)
        except OSError:
            pass  # Best-effort invalidation; preserve the original error.
        finally:
            os.close(fd)

    def write_rows(self, rows, fields):
        if self.directory is None:
            raise RuntimeError("benchmark output directory is not open")
        temporary = "." + self.destination.name + "." + secrets.token_hex(16) + ".tmp"
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=self.directory,
        )
        try:
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
                stream.flush()
                os.fsync(stream.fileno())
            published = os.stat(temporary, dir_fd=self.directory, follow_symlinks=False)
            identity = (published.st_dev, published.st_ino)
            os.replace(
                temporary, self.destination.name,
                src_dir_fd=self.directory, dst_dir_fd=self.directory,
            )
            temporary = None
            # Persist the directory-entry replacement as well as the CSV bytes.
            # A file fsync alone does not guarantee the rename survives a crash.
            try:
                os.fsync(self.directory)
            except OSError:
                # Do not upload an apparently valid artifact after a failed
                # durability barrier. Cleanup is best-effort; preserve error.
                self._cleanup_published(identity)
                raise
            # A renamed destination is still safe, but must not be certified
            # as published at the path the caller supplied.
            try:
                visible = os.stat(self.destination.parent, follow_symlinks=False)
            except OSError:
                # The path can disappear or become inaccessible after rename.
                # Remove evidence from the anchored directory before failing.
                self._cleanup_published(identity)
                raise
            if (visible.st_dev, visible.st_ino) != self.opened_identity:
                # Publication reached the original inode, not the requested
                # pathname. Do not leave apparently valid evidence behind.
                self._cleanup_published(identity)  # Preserve the directory-identity failure.
                raise ValueError("benchmark output directory changed during publication")
        finally:
            if temporary is not None:
                # An unlink failure must not replace the original CSV write
                # failure. If no error was active, surface cleanup failure.
                failed = sys.exc_info()[0] is not None
                try:
                    os.unlink(temporary, dir_fd=self.directory)
                except FileNotFoundError:
                    pass
                except OSError:
                    if not failed:
                        raise

    def __exit__(self, *_exc):
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
