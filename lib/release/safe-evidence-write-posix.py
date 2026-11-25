#!/usr/bin/env python3
"""Handle-relative evidence replacement for Darwin's legacy release tools.

Uses only the standard library and openat/renameat through dir_fd. The parent
process binds the preflight identities. No path-only fallback is permitted.
"""
import json
import os
import secrets
import stat
import sys
from contextlib import ExitStack

MAX_BYTES = 64 * 1024 * 1024
MAX_HEADER = 64 * 1024


def identity(info):
    return (str(info.st_dev), str(info.st_ino))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def components(path):
    require(isinstance(path, str) and path and not path.startswith('/'), 'invalid relative path')
    parts = path.split('/')
    for part in parts:
        require(part not in ('', '.', '..') and not part.endswith(('.', ' '))
                and not any(ord(c) < 32 or c in '\\:<>"|?*' for c in part),
                'unsafe path component')
    return parts


def safe_file(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_ino != 0


def replace_evidence(request, payload):
    require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'),
            'descriptor-relative operations unavailable')
    require(os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.unlink in os.supports_dir_fd and os.rename in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks, 'required dir_fd operations unavailable')
    root = request['root']
    require(isinstance(root, str) and root.startswith('/') and os.path.realpath(root) == root,
            'root is not canonical')
    parts = components(request['relativePath'])
    expected = request['directories']
    require(isinstance(expected, list) and len(expected) == len(parts), 'directory binding mismatch')
    original = request['original']
    require(original is None or isinstance(original, list) and len(original) == 2,
            'invalid target binding')
    mode = request['mode']
    require(type(mode) is int and 0 <= mode <= 0o777, 'invalid mode')
    require(len(payload) == request['length'] and len(payload) <= MAX_BYTES, 'invalid payload length')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    with ExitStack() as stack:
        def hold(fd):
            stack.callback(os.close, fd)
            return fd

        parent = hold(os.open('/', flags))
        for part in root.split('/')[1:]:
            if part:
                parent = hold(os.open(part, flags, dir_fd=parent))
        bound = [(root, parent, tuple(expected[0]))]
        current = root
        for index, part in enumerate(parts[:-1], 1):
            parent = hold(os.open(part, flags, dir_fd=parent))
            current = os.path.join(current, part)
            bound.append((current, parent, tuple(expected[index])))

        def verify_directories():
            for public, fd, wanted in bound:
                public_info = os.lstat(public)
                opened = os.fstat(fd)
                require(stat.S_ISDIR(public_info.st_mode) and stat.S_ISDIR(opened.st_mode)
                        and opened.st_ino != 0 and identity(public_info) == wanted
                        and identity(opened) == wanted, 'directory identity changed')

        target = parts[-1]

        def at(name):
            try:
                return os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def verify_target():
            info = at(target)
            require((original is None and info is None) or
                    (original is not None and info is not None and safe_file(info)
                     and identity(info) == tuple(original)), 'target identity changed or unsafe')

        verify_directories()
        verify_target()
        temporary = '.armorbreak-' + secrets.token_hex(16) + '.tmp'
        temporary_identity = None
        try:
            output = hold(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  mode, dir_fd=parent))
            opened = os.fstat(output)
            temporary_identity = identity(opened)
            entry = at(temporary)
            require(safe_file(opened) and entry is not None and safe_file(entry)
                    and identity(entry) == temporary_identity, 'temporary file identity changed')
            verify_directories()
            verify_target()
            view = memoryview(payload)
            while view:
                count = os.write(output, view)
                require(count > 0, 'write made no progress')
                view = view[count:]
            os.fsync(output)
            verify_directories()
            verify_target()
            entry = at(temporary)
            require(entry is not None and safe_file(entry) and identity(entry) == temporary_identity
                    and entry.st_size == len(payload), 'temporary file changed before rename')
            os.rename(temporary, target, src_dir_fd=parent, dst_dir_fd=parent)
            verify_directories()
            result = at(target)
            require(result is not None and safe_file(result) and identity(result) == temporary_identity
                    and result.st_size == len(payload), 'replacement identity changed')
        finally:
            entry = at(temporary)
            if temporary_identity is not None and entry is not None and safe_file(entry) and identity(entry) == temporary_identity:
                os.unlink(temporary, dir_fd=parent)


def main():
    try:
        header = sys.stdin.buffer.readline(MAX_HEADER + 1)
        require(len(header) <= MAX_HEADER and header.endswith(b'\n'), 'invalid request header')
        request = json.loads(header)
        length = request['length']
        require(type(length) is int and 0 <= length <= MAX_BYTES, 'invalid request length')
        payload = sys.stdin.buffer.read(length + 1)
        replace_evidence(request, payload)
        print('SAFE_POSIX_EVIDENCE_WRITE_OK')
    except (OSError, ValueError, KeyError, TypeError):
        print('SAFE_POSIX_EVIDENCE_WRITE_REFUSED', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
