"""Generic, journaled POSIX permission transaction and fail-closed helpers.

No server addresses, credentials, private application source, deployments or
backup configuration are contained in this module. A private entry point must
supply and validate its exact scope before using Transaction.
"""
import json
import hashlib
import os
import secrets
import stat
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

class Blocked(RuntimeError):
    pass

def need(ok, message):
    if not ok:
        raise Blocked(message)

def private_json(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.journal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def no_links(path):
    path = Path(path)
    need(path.is_absolute(), 'ABSOLUTE_PATH_REQUIRED')
    for component in reversed((path, *path.parents)):
        s = component.lstat()
        need(not stat.S_ISLNK(s.st_mode), 'SYMLINK_REFUSED')
    need(path.resolve() == path, 'NON_CANONICAL_PATH')

def metadata(path):
    no_links(path)
    s = path.lstat()
    is_dir = stat.S_ISDIR(s.st_mode)
    need(is_dir or stat.S_ISREG(s.st_mode), 'SPECIAL_FILE_REFUSED')
    need(is_dir or s.st_nlink == 1, 'HARDLINK_REFUSED')
    attrs = os.listxattr(path, follow_symlinks=False)
    need(not any(x in attrs for x in ('system.posix_acl_access', 'system.posix_acl_default')),
         'ACL_REQUIRES_REVIEW')
    return dict(path=str(path), device=s.st_dev, inode=s.st_ino,
                uid=s.st_uid, gid=s.st_gid, mode=stat.S_IMODE(s.st_mode), directory=is_dir)

def same_object(a, b):
    return all(a[x] == b[x] for x in ('device', 'inode', 'uid', 'gid', 'directory'))

class Transaction:
    """Only ten prevalidated objects. Journal intention BEFORE every fchmod.

    Automatic recovery keeps closed directories closed. Exact unsafe directory
    rollback (777/755) is deliberately NOT automatic.
    """
    def __init__(self, items, journal, pre_change=None):
        self.items, self.journal = items, journal
        self.operations = []
        self.pre_change = pre_change or (lambda: None)
        self.phase = 'PREPARED'
        self.transaction_id = secrets.token_hex(16)

    def save(self):
        private_json(self.journal, dict(schema_version=2, transaction_id=self.transaction_id,
                                       phase=self.phase, items=self.items, operations=self.operations))

    def set_mode(self, original, mode):
        self.pre_change()
        now = metadata(Path(original['path']))
        need(same_object(now, original), 'OBJECT_CHANGED')
        need(now['mode'] == original['mode'], 'MODE_CHANGED_CONCURRENTLY')
        if now['mode'] == mode:
            return
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if now['directory']:
            flags |= os.O_DIRECTORY
        fd = os.open(original['path'], flags)
        try:
            s = os.fstat(fd)
            need((s.st_dev, s.st_ino, s.st_uid, s.st_gid) ==
                 tuple(original[k] for k in ('device', 'inode', 'uid', 'gid')), 'FD_IDENTITY_CHANGED')
            op = dict(path=original['path'], before=original['mode'], after=mode, state='INTENT')
            self.operations.append(op)
            self.save()  # If this fails, no chmod.
            os.fchmod(fd, mode)
            need(stat.S_IMODE(os.fstat(fd).st_mode) == mode, 'CHMOD_FAILED')
            op['state'] = 'VERIFIED'
            self.save()
        finally:
            os.close(fd)

    def apply(self):
        self.phase = 'APPLYING'
        self.save()
        # Close each known directory before its files; no recursive traversal.
        for directory in [x for x in self.items if x['directory']]:
            self.set_mode(directory, 0o700)
            for item in self.items:
                if not item['directory'] and Path(item['path']).parent == Path(directory['path']):
                    self.set_mode(item, 0o600)
        self.phase = 'APPLIED'
        self.save()

    def commit(self):
        need(self.phase == 'APPLIED', 'TRANSACTION_NOT_APPLIED')
        self.phase = 'COMMITTED'
        self.save()

    def rollback(self):
        failures = []
        self.phase = 'ROLLING_BACK'
        try:
            self.save()
        except Exception:
            failures.append(str(self.journal))
        for op in reversed(self.operations):
            original = next(x for x in self.items if x['path'] == op['path'])
            try:
                now = metadata(Path(op['path']))
                need(same_object(now, original), 'ROLLBACK_OBJECT_CHANGED')
                if op['state'] == 'INTENT' and now['mode'] == op['before']:
                    op['state'] = 'NOT_APPLIED'
                    self.save()
                    continue
                target = 0o700 if original['directory'] else original['mode']
                need(now['mode'] in (op['before'], op['after']), 'ROLLBACK_MODE_CHANGED')
                fd = os.open(op['path'], os.O_RDONLY | os.O_NOFOLLOW |
                             (os.O_DIRECTORY if original['directory'] else 0))
                try:
                    s = os.fstat(fd)
                    need((s.st_dev, s.st_ino, s.st_uid, s.st_gid) ==
                         tuple(original[k] for k in ('device', 'inode', 'uid', 'gid')),
                         'ROLLBACK_FD_CHANGED')
                    os.fchmod(fd, target)
                    need(stat.S_IMODE(os.fstat(fd).st_mode) == target, 'ROLLBACK_VERIFY_FAILED')
                finally:
                    os.close(fd)
                op['state'] = 'CONTAINED' if original['directory'] else 'REVERTED'
                self.save()
            except Exception:
                failures.append(op['path'])
        self.phase = 'ROLLBACK_INCOMPLETE' if failures else 'ROLLED_BACK_CONTAINED'
        try:
            self.save()
        except Exception:
            failures.append(str(self.journal))
            self.phase = 'ROLLBACK_INCOMPLETE'
        return dict(status=self.phase,
                    pending_paths=failures)


def load_recovery(journal, policy, required_uid=0):
    """Recover a private interrupted journal only within caller-pinned exact scope.

    policy maps each permitted absolute path to uid, gid, directory and allowed
    original modes. Caller must supply its own trusted policy, never the journal.
    Committed journals are not permission rollback instructions.
    """
    jm, parent = metadata(journal), metadata(journal.parent)
    need(not jm['directory'] and jm['uid'] == required_uid and jm['mode'] == 0o600,
         'RECOVERY_JOURNAL_NOT_PRIVATE')
    need(parent['directory'] and parent['uid'] == required_uid and parent['mode'] == 0o700,
         'RECOVERY_PARENT_NOT_PRIVATE')
    data = json.loads(journal.read_text())
    need(data.get('schema_version') == 2, 'RECOVERY_SCHEMA_UNSUPPORTED')
    need(data.get('phase') in ('PREPARED','APPLYING','APPLIED','ROLLING_BACK','ROLLBACK_INCOMPLETE'),
         'RECOVERY_PHASE_NOT_INTERRUPTED')
    tid = data.get('transaction_id')
    need(isinstance(tid, str) and len(tid) == 32 and all(x in '0123456789abcdef' for x in tid),
         'RECOVERY_ID_INVALID')
    items = data.get('items', [])
    need(len(items) == len(policy) and {x.get('path') for x in items} == set(policy),
         'RECOVERY_SCOPE_DIFFERS')
    need(len({x['path'] for x in items}) == len(items), 'RECOVERY_DUPLICATE_OBJECT')
    for item in items:
        expected = policy[item['path']]
        need(all(item.get(k) == expected[k] for k in ('uid','gid','directory')) and
             item.get('mode') in expected['modes'], 'RECOVERY_POLICY_DIFFERS')
        need(all(type(item.get(k)) is int and item[k] >= 0 for k in ('device','inode')),
             'RECOVERY_METADATA_INVALID')
    operations = data.get('operations', [])
    need(len(operations) <= len(items) and len({x.get('path') for x in operations}) == len(operations),
         'RECOVERY_OPERATIONS_INVALID')
    for op in operations:
        need(op.get('path') in policy and op.get('state') in ('INTENT','VERIFIED','NOT_APPLIED','CONTAINED','REVERTED'),
             'RECOVERY_OPERATION_INVALID')
        item = next(x for x in items if x['path'] == op['path'])
        need(op.get('before') == item['mode'] and
             op.get('after') == (0o700 if item['directory'] else 0o600), 'RECOVERY_MODE_INVALID')
    tx = Transaction(items, journal)
    tx.operations = operations
    tx.phase, tx.transaction_id = data['phase'], tid
    return tx

def json_pointer(value, pointer):
    need(isinstance(pointer, str) and pointer.startswith('/'), 'CONFIG_SELECTOR_INVALID')
    for part in pointer[1:].split('/'):
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value

def cron_next(expression, zone, now):
    """Only conventional five-field cron; unknown dialects fail closed."""
    fields = expression.split()
    need(len(fields) == 5, 'CRON_DIALECT_UNSUPPORTED')
    need(fields[2] == '*' or fields[4] == '*', 'CRON_DAY_SEMANTICS_UNSUPPORTED')
    def values(field, low, high):
        found = set()
        for piece in field.split(','):
            base, sep, step = piece.partition('/')
            need(not sep or base == '*' or '-' in base, 'CRON_STEP_DIALECT_UNSUPPORTED')
            stride = int(step) if sep else 1
            need(stride > 0, 'CRON_INVALID')
            if base == '*': a, b = low, high
            elif '-' in base: a, b = map(int, base.split('-'))
            else: a = b = int(base)
            need(low <= a <= b <= high, 'CRON_INVALID')
            found.update(range(a, b + 1, stride))
        return found
    mins, hours, days, months, weekdays = [values(f, *bounds) for f, bounds in
        zip(fields, ((0,59),(0,23),(1,31),(1,12),(0,7)))]
    tz = ZoneInfo(zone)
    point = datetime.fromtimestamp(now, timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        local = point.astimezone(tz)
        week = (local.weekday() + 1) % 7
        dom, dow = local.day in days, week in weekdays or (week == 0 and 7 in weekdays)
        day_ok = (dom and dow) if fields[2] == '*' or fields[4] == '*' else (dom or dow)
        if local.minute in mins and local.hour in hours and local.month in months and day_ok:
            return point.timestamp()
        point += timedelta(minutes=1)
    raise Blocked('CRON_WINDOW_UNRESOLVED')


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()
