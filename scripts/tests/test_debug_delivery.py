"""Opaque byte fixtures test bundle integrity, never APK validity."""

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-debug-delivery.py'
SPEC = importlib.util.spec_from_file_location('debug_delivery', SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
SOURCE = 'a' * 40


class DeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.apk = self.root / V.APK_NAME
        self.checksum = self.root / (V.APK_NAME + '.sha256')
        self.meta = self.root / V.METADATA_NAME
        self.apk.write_bytes(b'opaque fixture; not a valid APK\x00\xff')
        self.digest = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.data = dict(V.FIXED, sha256=self.digest, sourceCommit=SOURCE,
                         sourceDirty=False)
        self.checksum.write_bytes((self.digest + '  ' + V.APK_NAME + '\n').encode())
        self.save()

    def save(self):
        self.meta.write_text(json.dumps(self.data), encoding='utf-8')

    def verify(self):
        V.verify(SOURCE, str(self.apk), str(self.checksum), str(self.meta))

    def denied(self):
        with self.assertRaises((V.Rejected, OSError, ValueError)):
            self.verify()

    def cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = V.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def arguments(self):
        return ['--source', SOURCE, '--apk', str(self.apk), '--checksum',
                str(self.checksum), '--metadata', str(self.meta)]

    def test_valid_bundle_and_exact_safe_cli(self):
        self.verify()
        self.assertEqual((0, V.SUCCESS + '\n', ''), self.cli(self.arguments()))

    def test_default_dist_paths(self):
        dist = self.root / 'dist'
        dist.mkdir()
        for path in (self.apk, self.checksum, self.meta):
            path.rename(dist / path.name)
        previous = os.getcwd()
        try:
            os.chdir(self.root)
            self.assertEqual((0, V.SUCCESS + '\n', ''),
                             self.cli(['--source', SOURCE]))
        finally:
            os.chdir(previous)

    def test_every_missing_input(self):
        for path in (self.apk, self.checksum, self.meta):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                path.unlink()
                self.denied()
                path.write_bytes(raw)

    def test_altered_and_mixed_bundles(self):
        self.apk.write_bytes(b'different opaque bytes')
        self.denied()
        self.data['sha256'] = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.save()
        self.denied()  # Metadata alone cannot repair stale checksum.
        self.checksum.write_text(self.data['sha256'] + '  ' + V.APK_NAME + '\n')
        self.verify()

    def test_exact_schema_types_values_and_unknown_keys(self):
        original = self.data.copy()
        for key, value in original.items():
            for bad in (None, True, False, 0, 1, [], {}, 'private-input-marker'):
                if type(bad) is type(value) and bad == value:
                    continue
                with self.subTest(key=key, bad=bad):
                    self.data = dict(original, **{key: bad})
                    self.save()
                    self.denied()
            self.data = original.copy()
            del self.data[key]
            self.save()
            self.denied()
        self.data = dict(original, unknown='secret')
        self.save()
        self.denied()

    def test_dirty_source_never_claims_clean(self):
        self.data['sourceDirty'] = True
        self.save()
        self.assertEqual((1, '', 'bundle integrity rejected: dirty_source\n'),
                         self.cli(self.arguments()))

    def test_wrong_source_and_invalid_expected_sources(self):
        self.data['sourceCommit'] = 'b' * 40
        self.save()
        self.denied()
        for source in ('', 'A' * 40, 'g' * 40, 'a' * 39, 'a' * 41, SOURCE + '\n', None):
            with self.subTest(source=source), self.assertRaises(V.Rejected):
                V.verify(source, str(self.apk), str(self.checksum), str(self.meta))

    def test_strict_malformed_json(self):
        valid = json.dumps(self.data).encode()
        cases = [b'', b'\xff', b'\xef\xbb\xbf' + valid, valid + b' {}',
                 valid + b'\x00', b'[]', b'null', b'{',
                 b'{"sourceDirty":false,"sourceDirty":false}',
                 valid[:-1] + b',"sourceDirty":false}',
                 valid[:-1] + b',"source\\u0044irty":false}',
                 b'[' * 1000 + b']' * 1000,
                 b'{"nested":{"x":1,"x":2}}',
                 b'{"x":"unescaped\ncontrol"}']
        cases.extend(b'{"x":' + n + b'}' for n in
                     (b'NaN', b'Infinity', b'-Infinity', b'1e999', b'1.0',
                      b'-0', b'01', b'1', b'9' * 10000))
        for raw in cases:
            with self.subTest(raw=raw[:50]):
                self.meta.write_bytes(raw)
                self.denied()

    def test_exact_checksum_line_and_stable_filename(self):
        valid = self.checksum.read_bytes()
        for raw in (valid.rstrip(b'\n'), valid + b'\n', valid + valid,
                    valid.replace(b'  ', b' '), valid.replace(b'\n', b'\r\n'),
                    valid.upper(), b'\xef\xbb\xbf' + valid,
                    valid.replace(V.APK_NAME.encode(), b'../private.apk'),
                    valid.replace(V.APK_NAME.encode(), b'other.apk'),
                    valid.replace(b'  ', b' *'), b'\xff'):
            with self.subTest(raw=raw[:80]):
                self.checksum.write_bytes(raw)
                self.denied()

    def test_size_bounds_all_inputs(self):
        for path, limit in ((self.apk, V.APK_LIMIT), (self.meta, V.METADATA_LIMIT),
                            (self.checksum, V.CHECKSUM_LIMIT)):
            original = path.read_bytes()
            for size in (0, limit + 1):
                with self.subTest(path=path.name, size=size):
                    with path.open('wb') as handle:
                        handle.truncate(size)  # Sparse APK, no huge allocation.
                    self.denied()
            path.write_bytes(original)

    def test_streaming_hash_and_read_growth_bound(self):
        self.apk.write_bytes(b'x' * (200 * 1024))
        self.digest = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.data['sha256'] = self.digest
        self.save()
        self.checksum.write_text(self.digest + '  ' + V.APK_NAME + '\n')
        real_read = os.read
        sizes = []

        def read(fd, size):
            sizes.append(size)
            return real_read(fd, size)

        with mock.patch.object(V.os, 'read', side_effect=read):
            self.verify()
        self.assertLessEqual(max(sizes), 65536)
        self.assertGreater(len(sizes), 6)
        fd = os.open(self.apk, os.O_RDONLY)
        try:
            with self.assertRaises(V.Rejected):
                V.read_bounded(fd, 16, hashlib.sha256())
        finally:
            os.close(fd)

    def test_symlink_each_file_and_ancestor(self):
        for path in (self.apk, self.checksum, self.meta):
            backup = path.with_suffix('.backup')
            path.rename(backup)
            path.symlink_to(backup)
            self.denied()
            path.unlink()
            backup.rename(path)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(V.Rejected):
            V.verify(SOURCE, str(alias / self.apk.name), str(self.checksum), str(self.meta))
        with self.assertRaises(V.Rejected):
            V.verify(SOURCE, str(alias / '..' / self.apk.name), str(self.checksum), str(self.meta))

    def test_nonregular_files_and_ancestor(self):
        original = self.apk.read_bytes()
        self.apk.unlink()
        self.apk.mkdir()
        self.denied()
        self.apk.rmdir()
        os.mkfifo(self.apk)
        self.denied()  # Must reject before any potentially blocking read.
        self.apk.unlink()
        self.apk.write_bytes(original)
        with self.assertRaises((OSError, V.Rejected)):
            V.verify(SOURCE, str(self.apk / 'child'), str(self.checksum), str(self.meta))

    def test_unsafe_and_bounded_paths(self):
        for path in ('', '\x00secret', 'x' * 4097, '/tmp/../private',
                     '/tmp//private', '/tmp/./private', '/tmp/evil\\name',
                     '/' + '/'.join(['x'] * 129)):
            with self.subTest(path=path), self.assertRaises(V.Rejected):
                with V.Inputs() as inputs:
                    inputs.open(path, 100)

    def test_race_file_replacement_after_reads(self):
        real_check = V.Inputs.check

        def replace(inputs):
            replacement = self.root / 'replacement'
            replacement.write_bytes(self.apk.read_bytes())
            replacement.replace(self.apk)
            real_check(inputs)

        with mock.patch.object(V.Inputs, 'check', replace):
            self.denied()

    def test_race_ancestor_replaced_by_symlink(self):
        original = self.root
        moved = self.root.with_name(self.root.name + '-moved')
        real_check = V.Inputs.check

        def replace(inputs):
            original.rename(moved)
            original.symlink_to(moved, target_is_directory=True)
            real_check(inputs)

        try:
            with mock.patch.object(V.Inputs, 'check', replace):
                self.denied()
        finally:
            if original.is_symlink():
                original.unlink()
                moved.rename(original)

    def test_race_between_stat_and_open(self):
        real_open = os.open
        changed = False

        def replace(path, flags, **kwargs):
            nonlocal changed
            if path == self.apk.name and not changed:
                changed = True
                new = self.root / 'new'
                new.write_bytes(self.apk.read_bytes())
                new.replace(self.apk)
            return real_open(path, flags, **kwargs)

        # Platform capability check uses function identity before patching open.
        with mock.patch.object(V, 'safe_platform'), \
                mock.patch.object(V.os, 'open', side_effect=replace):
            self.denied()
        self.assertTrue(changed)

    def test_nofollow_symlink_race_between_stat_and_open(self):
        real_open = os.open
        changed = False

        def replace(path, flags, **kwargs):
            nonlocal changed
            if path == self.apk.name and not changed:
                changed = True
                backup = self.root / 'backup'
                self.apk.rename(backup)
                self.apk.symlink_to(backup)
            return real_open(path, flags, **kwargs)

        with mock.patch.object(V, 'safe_platform'), \
                mock.patch.object(V.os, 'open', side_effect=replace):
            self.denied()
        self.assertTrue(changed)

    def test_cross_file_replacement_during_hash_is_rejected(self):
        real_read = os.read
        changed = False

        def replace(fd, size):
            nonlocal changed
            raw = real_read(fd, size)
            if raw == self.apk.read_bytes() and not changed:
                changed = True
                replacement = self.root / 'new-checksum'
                replacement.write_bytes(self.checksum.read_bytes())
                replacement.replace(self.checksum)
            return raw

        with mock.patch.object(V.os, 'read', side_effect=replace):
            self.denied()
        self.assertTrue(changed)

    def test_metadata_exact_size_limit(self):
        raw = self.meta.read_bytes()
        self.meta.write_bytes(raw + b' ' * (V.METADATA_LIMIT - len(raw)))
        self.verify()
        self.meta.write_bytes(self.meta.read_bytes() + b' ')
        self.denied()

    def test_race_in_place_change_same_size(self):
        real_check = V.Inputs.check

        def change(inputs):
            before = self.apk.stat()
            self.apk.write_bytes(b'z' * before.st_size)
            # Immediate writes can share both timestamps on coarse filesystems.
            # Make this an observable identity change, without sleeps or retries.
            os.utime(self.apk, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
            after = self.apk.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size),
                             (after.st_dev, after.st_ino, after.st_size))
            self.assertNotEqual(before.st_mtime_ns, after.st_mtime_ns)
            real_check(inputs)

        with mock.patch.object(V.Inputs, 'check', change):
            self.denied()

    def test_platform_unavailable_fails_closed(self):
        with mock.patch.object(V.os, 'supports_dir_fd', set()):
            self.assertEqual((1, '', 'bundle integrity rejected: platform_unavailable\n'),
                             self.cli(self.arguments()))

    def test_cli_finite_failure_privacy_and_explicit_source(self):
        for args in ([], ['--source'], ['--source', 'private-input-marker'],
                     ['--source', SOURCE, '--unknown=private-input-marker'],
                     ['--sour', SOURCE], self.arguments() + ['private-input-marker'],
                     ['--source', SOURCE, '--apk', '/private-input-marker/absent']):
            with self.subTest(args=args):
                code, out, err = self.cli(args)
                self.assertEqual(code, 1)
                self.assertEqual(out, '')
                self.assertRegex(err, r'^bundle integrity rejected: [a-z_]+\n$')
                self.assertNotIn('private-input-marker', err)
                self.assertNotIn(str(self.root), err)
        self.meta.write_bytes(b'private-input-marker malformed metadata')
        self.assertEqual((1, '', 'bundle integrity rejected: invalid_input\n'),
                         self.cli(self.arguments()))

    def test_no_process_network_device_imports_or_write_calls(self):
        tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
        allowed = {'argparse', 'hashlib', 'json', 'os', 're', 'stat', 'sys'}
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names}
        self.assertEqual(imports, allowed)
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr,
                                 {'write', 'write_bytes', 'write_text', 'system',
                                  'popen', 'spawn', 'connect', 'socket', 'execv'})


if __name__ == '__main__':
    unittest.main()
