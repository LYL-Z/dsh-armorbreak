"""Actual filesystem regressions for the descriptor-relative evidence helper."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'lib/release/safe-evidence-write-posix.py'
spec = importlib.util.spec_from_file_location('native_evidence_writer', HELPER)
writer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)


class NativeWriter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.parent = self.root / 'evidence'
        self.parent.mkdir()
        self.target = self.parent / 'result.json'
        self.target.write_bytes(b'original')
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        self.sentinel = self.outside / 'result.json'
        self.sentinel.write_bytes(b'outside sentinel')
        self.held = self.root / 'held'

    def request(self, payload=b'updated'):
        return {'root': str(self.root), 'relativePath': 'evidence/result.json',
                'directories': [list(writer.identity(p.lstat())) for p in (self.root, self.parent)],
                'original': list(writer.identity(self.target.lstat())) if self.target.exists() else None,
                'mode': 0o600, 'length': len(payload)}

    def swap_parent(self):
        self.parent.rename(self.held)
        self.parent.symlink_to(self.outside, target_is_directory=True)

    def test_replacement_and_new_target(self):
        writer.replace_evidence(self.request(), b'updated')
        self.assertEqual(self.target.read_bytes(), b'updated')
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.target.unlink()
        writer.replace_evidence(self.request(), b'updated')
        self.assertEqual(self.target.read_bytes(), b'updated')
        self.assertEqual(list(self.parent.iterdir()), [self.target])

    def test_stale_identity_does_not_replace(self):
        request = self.request()
        self.target.rename(self.parent / 'old')
        self.target.write_bytes(b'changed')
        with self.assertRaises((ValueError, OSError)):
            writer.replace_evidence(request, b'updated')
        self.assertEqual(self.target.read_bytes(), b'changed')

    def test_hard_link_refusal(self):
        os.link(self.target, self.parent / 'alias')
        with self.assertRaises((ValueError, OSError)):
            writer.replace_evidence(self.request(), b'updated')
        self.assertEqual(self.target.read_bytes(), b'original')

    def test_parent_swap_before_native_call(self):
        request = self.request()
        self.swap_parent()
        with self.assertRaises((ValueError, OSError)):
            writer.replace_evidence(request, b'updated')
        self.assertEqual(self.sentinel.read_bytes(), b'outside sentinel')
        self.assertEqual((self.held / 'result.json').read_bytes(), b'original')

    def test_parent_swap_at_temporary_open(self):
        request = self.request()
        real_open = os.open
        swapped = False

        def open_with_swap(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and str(path).endswith('.tmp'):
                self.swap_parent()
                swapped = True
            return real_open(path, flags, *args, **kwargs)

        with patch.object(os, 'open', open_with_swap), patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {open_with_swap}):
            with self.assertRaises((ValueError, OSError)):
                writer.replace_evidence(request, b'updated')
        self.assertTrue(swapped)
        self.assertEqual(self.sentinel.read_bytes(), b'outside sentinel')
        self.assertEqual((self.held / 'result.json').read_bytes(), b'original')
        self.assertEqual(sorted(p.name for p in self.held.iterdir()), ['result.json'])

    def test_parent_swap_at_final_rename(self):
        request = self.request()
        real_rename = os.rename
        swapped = False

        def rename_with_swap(src, dst, *args, **kwargs):
            nonlocal swapped
            if not swapped and dst == 'result.json' and 'dst_dir_fd' in kwargs:
                swapped = True
                real_rename(self.parent, self.held)
                self.parent.symlink_to(self.outside, target_is_directory=True)
            return real_rename(src, dst, *args, **kwargs)

        with patch.object(os, 'rename', rename_with_swap), patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {rename_with_swap}):
            with self.assertRaises((ValueError, OSError)):
                writer.replace_evidence(request, b'updated')
        self.assertTrue(swapped)
        self.assertEqual(self.sentinel.read_bytes(), b'outside sentinel')
        self.assertEqual((self.held / 'result.json').read_bytes(), b'updated')

    def test_invalid_input_refuses(self):
        request = self.request()
        request['relativePath'] = '../outside/result.json'
        with self.assertRaises((ValueError, OSError)):
            writer.replace_evidence(request, b'updated')
        self.assertEqual(self.sentinel.read_bytes(), b'outside sentinel')
        self.assertEqual(self.target.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main(verbosity=2)
