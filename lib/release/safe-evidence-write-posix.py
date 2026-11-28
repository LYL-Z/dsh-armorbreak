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
import threading
import time
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


def frame_grace_seconds():
    raw = os.environ.get('ARMORBREAK_EVIDENCE_FRAME_GRACE_MS', '50')
    try:
        milliseconds = float(raw)
    except ValueError:
        milliseconds = 50
    if milliseconds < 0 or milliseconds > 2000:
        milliseconds = 50
    return milliseconds / 1000


def read_exact(raw, size):
    """Read at most `size` bytes from an unbuffered stream. No lookahead."""
    payload = bytearray()
    while len(payload) < size:
        chunk = raw.read(size - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def read_header_line(raw):
    # One byte at a time so the payload is never pulled into a user-space buffer
    # ahead of the length prefix. BufferedReader.read(n) can hide a trailing byte
    # from a later select() on the same pipe.
    header = bytearray()
    while len(header) <= MAX_HEADER and not header.endswith(b'\n'):
        byte = raw.read(1)
        if not byte:
            break
        header.extend(byte)
    return bytes(header)


def _nonblocking_available():
    # os.get_blocking is Unix-only. Windows CPython raises AttributeError, and the
    # frame tests still execute this helper there. A threaded read is the portable
    # grace-period implementation; Darwin keeps the non-blocking path.
    if os.environ.get('ARMORBREAK_EVIDENCE_FRAME_IO') == 'thread':
        return False
    return hasattr(os, 'get_blocking') and hasattr(os, 'set_blocking')


def _read_trailer_nonblocking(raw, grace):
    fd = raw.fileno()
    was_blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    try:
        deadline = time.monotonic() + grace
        while True:
            try:
                extra = raw.read(1)
            except BlockingIOError:
                extra = None
            if extra is None:
                if time.monotonic() >= deadline:
                    return b''
                time.sleep(0.005)
                continue
            return extra
    finally:
        os.set_blocking(fd, was_blocking)


def _read_trailer_threaded(raw, grace):
    box = {}

    def _read():
        try:
            box['extra'] = raw.read(1)
        except OSError as error:
            box['error'] = error

    worker = threading.Thread(target=_read, daemon=True)
    worker.start()
    worker.join(grace)
    if 'error' in box:
        raise box['error']
    # Still blocked: the pipe stayed open and no trailer arrived within grace.
    # The daemon read ends when this process exits; the declared frame is complete.
    return box.get('extra', b'')


def read_trailer(raw, grace):
    """Return b'' for EOF or a still-open pipe, or the first extra byte.

    Bytes are read from the raw stream, which has no user-space buffer, so a
    trailing byte already accepted by the kernel cannot hide from the check.
    """
    if _nonblocking_available():
        return _read_trailer_nonblocking(raw, grace)
    return _read_trailer_threaded(raw, grace)


def read_frame(raw):
    header = read_header_line(raw)
    require(header and len(header) <= MAX_HEADER and header.endswith(b'\n'), 'invalid request header')
    request = json.loads(header)
    length = request['length']
    require(type(length) is int and 0 <= length <= MAX_BYTES, 'invalid request length')
    payload = read_exact(raw, length)
    require(len(payload) == length, 'incomplete payload')
    extra = read_trailer(raw, frame_grace_seconds())
    require(extra == b'', 'trailing payload bytes')
    return request, payload


def main():
    raw = sys.stdin.buffer.detach()
    try:
        request, payload = read_frame(raw)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'SAFE_POSIX_EVIDENCE_FRAME_REFUSED {error}', file=sys.stderr)
        return 1
    try:
        replace_evidence(request, payload)
        print('SAFE_POSIX_EVIDENCE_WRITE_OK')
    except (OSError, ValueError, KeyError, TypeError):
        print('SAFE_POSIX_EVIDENCE_WRITE_REFUSED', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
