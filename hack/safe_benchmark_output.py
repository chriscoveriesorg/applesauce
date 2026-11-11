#!/usr/bin/env python3
"""Descriptor-anchored, fail-closed publication of derived benchmark CSVs.

The workflow resets generated evidence before running exporters, and uploads
derived CSVs only on success. Never unlink an occupied destination or mutate
an already-published inode: concurrent path/hardlink substitution can damage
an unrelated file. Publication is exclusive and anchored to one directory.
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
            # Every exporter writes into a freshly reset evidence directory.
            # Refuse an occupied entry instead of deleting it: a concurrent
            # same-UID writer could substitute an unrelated pathname between
            # validation and unlink. Exclusive publication below is the final
            # protection against a second writer appearing after this check.
            try:
                current = os.stat(output.name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None:
                for source in self.sources:
                    try:
                        source_stat = os.stat(source, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if (current.st_dev, current.st_ino) == (
                        source_stat.st_dev, source_stat.st_ino
                    ):
                        raise ValueError("benchmark output must differ from source evidence")
                raise FileExistsError(
                    "benchmark output already exists; reset generated evidence first"
                )
            self.directory = fd
            self.opened_identity = (opened.st_dev, opened.st_ino)
            return self
        except BaseException:
            os.close(fd)
            raise

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
            # Exclusive hard-link publication atomically refuses an occupied
            # destination. os.replace() would silently overwrite a pathname
            # introduced by another writer after __enter__ preflight.
            os.link(
                temporary, self.destination.name,
                src_dir_fd=self.directory, dst_dir_fd=self.directory,
                follow_symlinks=False,
            )
            # Unlink only our random temporary entry; never remove or
            # truncate the final destination after publication.
            os.unlink(temporary, dir_fd=self.directory)
            temporary = None
            # Directory durability can fail after a visible publication. The
            # workflow must treat this as a failed run and upload diagnostics
            # only, never derived CSVs. The published inode is left intact:
            # truncation would damage a concurrently created hardlink.
            os.fsync(self.directory)
            visible = os.stat(self.destination.parent, follow_symlinks=False)
            if (visible.st_dev, visible.st_ino) != self.opened_identity:
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
