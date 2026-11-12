"""Portable regression for pinned read-only kernelcache source ownership."""
import errno
import os
from pathlib import Path
import unittest
from unittest import mock

import decmpfs_binary_probe as probe


class SourceOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_fstat_failure_closes_new_descriptor(self):
        with mock.patch.object(probe.os, "open", return_value=123) as opened, \
             mock.patch.object(probe.os, "fstat", side_effect=OSError(errno.EIO, "injected")) as stated, \
             mock.patch.object(probe.os, "close") as closed:
            with self.assertRaises(OSError) as caught:
                probe.Source(Path("unused-generated-fixture"))
        self.assertEqual(caught.exception.errno, errno.EIO)
        opened.assert_called_once()
        stated.assert_called_once_with(123)
        closed.assert_called_once_with(123)


    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
    def test_fstat_failure_preserved_when_close_also_fails(self):
        with mock.patch.object(probe.os, "open", return_value=123), \
             mock.patch.object(probe.os, "fstat", side_effect=OSError(errno.EIO, "inspection failed")), \
             mock.patch.object(probe.os, "close", side_effect=OSError(errno.EBADF, "cleanup failed")) as closed:
            with self.assertRaises(OSError) as caught:
                probe.Source(Path("unused-generated-fixture"))
        self.assertEqual(caught.exception.errno, errno.EIO)
        closed.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
