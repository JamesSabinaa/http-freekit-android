#!/usr/bin/env python3
"""Offline bundle consistency only; metadata is not APK/provenance attestation.

Requires POSIX descriptor-relative no-follow operations; other platforms fail
closed. Only a producer-reported clean source is accepted (dirty builds fail).
Version, protocol, capabilities and signing are self-reported, not extracted or
verified from the APK. Even matching hashes do not authenticate the producer.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys

APK_NAME = 'http-freekit-android-debug.apk'
METADATA_NAME = 'http-freekit-android-debug-metadata.json'
APK_LIMIT = 256 * 1024 * 1024
METADATA_LIMIT = 32 * 1024
CHECKSUM_LIMIT = 512
SUCCESS = ('bundle integrity verified; desktop compatibility unavailable; '
           'device/USB not assessed')
FIXED = {
    'artifact': APK_NAME,
    'version': '0.1.0-dev-debug',
    'protocol': 'v1-draft-not-integrated',
    'compatibleDesktopCommit': None,
    'installedAppDiscoveryImplemented': True,
    'captureImplemented': False,
    'signing': 'local Android debug key; not a release identity',
}


class Rejected(Exception):
    """Finite public reason, never input or exception text."""


def reject(code):
    raise Rejected(code)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def safe_platform():
    if (os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW')
            or not hasattr(os, 'O_DIRECTORY') or not hasattr(os, 'O_NONBLOCK')
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks):
        reject('platform_unavailable')


class Inputs:
    """Retain every descriptor and recheck directory entries after all reads."""

    def __init__(self):
        self.fds = []
        self.entries = []

    def __enter__(self):
        safe_platform()
        return self

    def __exit__(self, *_):
        for fd in reversed(self.fds):
            os.close(fd)

    def open(self, path, limit):
        if (type(path) is not str or not path or len(path) > 4096
                or '\x00' in path or '\\' in path):
            reject('unsafe_path')
        if any(p in ('.', '..') for p in path.split('/')):
            reject('unsafe_path')
        path = os.path.abspath(path) if not path.startswith('/') else path
        parts = path.split('/')[1:]
        if len(parts) > 128 or any(p in ('', '.', '..') for p in parts):
            reject('unsafe_path')
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.fds.append(parent)
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not (stat.S_ISREG(before.st_mode) if final
                    else stat.S_ISDIR(before.st_mode)):
                reject('unsafe_file')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if not final:
                flags |= os.O_DIRECTORY
            fd = os.open(part, flags, dir_fd=parent)
            self.fds.append(fd)
            opened = os.fstat(fd)
            if identity(before) != identity(opened):
                reject('input_changed')
            self.entries.append((parent, part, fd, identity(opened), final))
            parent = fd
        if opened.st_size < 1 or opened.st_size > limit:
            reject('size_limit')
        return fd

    def check(self):
        for parent, name, fd, original, final in self.entries:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            # Directory sizes/times can change for unrelated children. Identity
            # and type still must match; final file snapshots match in full.
            width = 6 if final else 3
            if (identity(current)[:width] != original[:width]
                    or identity(held)[:width] != original[:width]):
                reject('input_changed')


def read_bounded(fd, limit, digest=None):
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            reject('size_limit')
        if digest is None:
            chunks.append(chunk)
        else:
            digest.update(chunk)
    if total != os.fstat(fd).st_size or total == 0:
        reject('input_changed')
    return b''.join(chunks) if digest is None else digest.hexdigest()


def no_number(_):
    reject('invalid_metadata')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject('invalid_metadata')
        result[key] = value
    return result


def metadata(raw, source):
    if raw.startswith(b'\xef\xbb\xbf'):
        reject('invalid_metadata')
    text = raw.decode('utf-8', errors='strict')
    # Bound nesting before invoking the JSON decoder, including hostile arrays.
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > 8:
                reject('invalid_metadata')
        elif char in ']}':
            depth -= 1
    value = json.loads(text, object_pairs_hook=unique_object,
                       parse_int=no_number, parse_float=no_number,
                       parse_constant=no_number)
    if type(value) is not dict or set(value) != set(FIXED) | {
            'sha256', 'sourceCommit', 'sourceDirty'}:
        reject('invalid_metadata')
    for key, expected in FIXED.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            reject('invalid_metadata')
    if type(value['sourceDirty']) is not bool:
        reject('invalid_metadata')
    if value['sourceDirty']:
        reject('dirty_source')
    if type(value['sourceCommit']) is not str or value['sourceCommit'] != source:
        reject('source_mismatch')
    if type(value['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', value['sha256']):
        reject('invalid_metadata')
    return value['sha256']


def verify(source, apk='dist/' + APK_NAME, checksum='dist/' + APK_NAME + '.sha256',
           metadata_path='dist/' + METADATA_NAME):
    if type(source) is not str or not re.fullmatch('[0-9a-f]{40}', source):
        reject('invalid_source')
    with Inputs() as inputs:
        apk_fd = inputs.open(apk, APK_LIMIT)
        checksum_fd = inputs.open(checksum, CHECKSUM_LIMIT)
        metadata_fd = inputs.open(metadata_path, METADATA_LIMIT)
        reported = metadata(read_bounded(metadata_fd, METADATA_LIMIT), source)
        line = read_bounded(checksum_fd, CHECKSUM_LIMIT)
        match = re.fullmatch(rb'([0-9a-f]{64})  http-freekit-android-debug\.apk\n', line)
        if match is None:
            reject('invalid_checksum')
        actual = read_bounded(apk_fd, APK_LIMIT, hashlib.sha256())
        inputs.check()
        if actual != reported or actual != match[1].decode('ascii'):
            reject('hash_mismatch')


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        reject('invalid_arguments')


def main(argv=None):
    try:
        parser = SafeParser(description=__doc__, allow_abbrev=False)
        parser.add_argument('--source', required=True)
        parser.add_argument('--apk', default='dist/' + APK_NAME)
        parser.add_argument('--checksum', default='dist/' + APK_NAME + '.sha256')
        parser.add_argument('--metadata', default='dist/' + METADATA_NAME)
        args = parser.parse_args(argv)
        verify(args.source, args.apk, args.checksum, args.metadata)
    except Rejected as error:
        print('bundle integrity rejected: ' + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, RecursionError, OverflowError):
        print('bundle integrity rejected: invalid_input', file=sys.stderr)
        return 1
    print(SUCCESS)
    return 0


if __name__ == '__main__':
    sys.exit(main())
