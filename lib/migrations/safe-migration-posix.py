#!/usr/bin/env python3
"""Bounded descriptor-relative I/O for the Darwin task-migration adapter."""
import hashlib
import json
import os
import secrets
import stat
import sys
from contextlib import ExitStack

LIMIT = 64 * 1024 * 1024
HEADER_LIMIT = 128 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def check(condition, message):
    if not condition:
        raise ValueError(message)


def identity(info):
    return [str(info.st_dev), str(info.st_ino)]


def safe_file(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_ino != 0


def trusted_owner(info):
    return info.st_uid in (0, os.geteuid())


def split_relative(path):
    parts = path.split('/')
    check(all(p not in ('', '.', '..') and '\x00' not in p for p in parts), 'unsafe component')
    return parts


def assert_operations():
    required = (os.open, os.stat, os.mkdir, os.unlink, os.rename)
    check(all(fn in os.supports_dir_fd for fn in required)
          and os.stat in os.supports_follow_symlinks, 'descriptor operations unavailable')


def run(request, payload):
    root = request['root']
    check(root.startswith('/') and os.path.normpath(root) == root, 'invalid workspace root')
    parts = split_relative(request['path'])
    parents = [p for p in root.split('/') if p] + parts[:-1]
    expected = request['parents']
    check(len(expected) == len(parents) + 1, 'directory binding length mismatch')
    name = parts[-1]
    operation = request['operation']
    with ExitStack() as stack:
        def hold(fd):
            stack.callback(os.close, fd)
            return fd

        parent = hold(os.open('/', DIRECTORY_FLAGS))
        bound = [('/', parent)]
        for part in parents:
            directory = hold(os.open(part, DIRECTORY_FLAGS, dir_fd=parent))
            parent_info, directory_info = os.fstat(parent), os.fstat(directory)
            check(trusted_owner(directory_info), 'directory controlled by another principal')
            check(not parent_info.st_mode & 0o022 or parent_info.st_mode & stat.S_ISVTX,
                  'untrusted writable parent')
            bound.append((os.path.join(bound[-1][0], part), directory))
            parent = directory

        def verify_parents():
            previous = None
            for (path, fd), wanted in zip(bound, expected):
                opened, public = os.fstat(fd), os.lstat(path)
                check(stat.S_ISDIR(public.st_mode) and opened.st_ino != 0
                      and trusted_owner(opened) and identity(opened) == wanted and identity(public) == wanted,
                      'directory identity changed')
                check(previous is None or not previous.st_mode & 0o022 or previous.st_mode & stat.S_ISVTX,
                      'untrusted writable parent')
                previous = opened
            check(not os.fstat(parent).st_mode & 0o022, 'untrusted writable destination')

        def entry(entry_name):
            try:
                return os.stat(entry_name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def verify_file(info, wanted):
            check(info is not None and safe_file(info) and trusted_owner(info)
                  and not info.st_mode & 0o022 and identity(info) == wanted,
                  'file identity or permissions changed')

        verify_parents()
        wanted = request['target']
        if operation == 'mkdir':
            check(wanted is None and entry(name) is None, 'new directory already exists')
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
            verify_parents()
            return b''

        old_fd = None
        original = entry(name)
        if wanted is None:
            check(operation == 'replace' and original is None, 'destination already exists')
        else:
            verify_file(original, wanted)
            flags = os.O_RDWR if operation == 'truncate' else os.O_RDONLY
            old_fd = hold(os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent))
            verify_file(os.fstat(old_fd), wanted)

        def read_bound():
            verify_parents()
            verify_file(entry(name), wanted)
            info = os.fstat(old_fd)
            verify_file(info, wanted)
            check(info.st_size <= LIMIT, 'file exceeds size limit')
            os.lseek(old_fd, 0, os.SEEK_SET)
            with os.fdopen(os.dup(old_fd), 'rb') as stream:
                value = stream.read(LIMIT + 1)
            after = os.fstat(old_fd)
            check(len(value) == info.st_size == after.st_size
                  and info.st_mtime_ns == after.st_mtime_ns and info.st_ctime_ns == after.st_ctime_ns,
                  'file changed while reading')
            verify_parents()
            verify_file(entry(name), wanted)
            return value

        if operation == 'read':
            return read_bound()

        def verify_before_change():
            verify_parents()
            if old_fd is None:
                check(entry(name) is None, 'destination appeared before commit')
            else:
                digest = hashlib.sha256(read_bound()).hexdigest()
                check(digest == request['beforeSha256'], 'file content changed before commit')

        if operation == 'truncate':
            verify_before_change()
            os.ftruncate(old_fd, 0)
            os.fsync(old_fd)
            verify_parents()
            verify_file(entry(name), wanted)
            return b''

        check(operation == 'replace', 'unknown operation')
        check(original is None or original.st_uid == os.geteuid(), 'replacement would change ownership')
        verify_before_change()
        temporary = '.armorbreak-migration-' + secrets.token_hex(16)
        fd = hold(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent))
        written_identity = identity(os.fstat(fd))
        try:
            if original is not None:
                os.fchown(fd, original.st_uid, original.st_gid)
                os.fchmod(fd, stat.S_IMODE(original.st_mode) & 0o777)
            verify_parents()
            verify_file(entry(temporary), written_identity)
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                check(count > 0, 'stalled write')
                view = view[count:]
            os.fsync(fd)
            verify_before_change()
            verify_file(entry(temporary), written_identity)
            check(os.fstat(fd).st_size == len(payload), 'temporary file size changed')
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            verify_parents()
            verify_file(entry(name), written_identity)
        finally:
            info = entry(temporary)
            if info is not None and safe_file(info) and identity(info) == written_identity:
                os.unlink(temporary, dir_fd=parent)
        return b''


def main():
    try:
        assert_operations()
        if sys.argv[1:] == ['--probe']:
            return 0
        header = sys.stdin.buffer.readline(HEADER_LIMIT + 1)
        check(len(header) <= HEADER_LIMIT and header.endswith(b'\n'), 'invalid request header')
        request = json.loads(header)
        length = request['length']
        check(type(length) is int and 0 <= length <= LIMIT, 'invalid payload limit')
        payload = sys.stdin.buffer.read(length + 1)
        check(len(payload) == length, 'invalid payload length')
        sys.stdout.buffer.write(run(request, payload))
        return 0
    except OSError as error:
        # Don't expose user directories or file content in subprocess diagnostics.
        print('MIGRATION_POSIX_OS_REFUSED errno=' + str(error.errno), file=sys.stderr)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        print('MIGRATION_POSIX_REFUSED ' + str(error), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
