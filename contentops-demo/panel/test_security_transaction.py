"""New transaction regressions only. No old ContentOps/restore tests run."""
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import security_transaction as s

class SecurityTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / 'data'
        self.data.mkdir(mode=511)
        os.chmod(self.data, 511)
        self.file = self.data / 'auth.sqlite'
        self.file.write_bytes(b'fictitious only')
        os.chmod(self.file, 420)
        self.items = [s.metadata(self.data), s.metadata(self.file)]
        self.tx = s.Transaction(self.items, self.root / 'journal.json')

    def tearDown(self):
        self.tmp.cleanup()

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def test_apply_and_preserve_bytes_identity(self):
        before = s.digest(self.file)
        self.tx.apply()
        self.assertEqual(self.mode(self.data), 448)
        self.assertEqual(self.mode(self.file), 384)
        self.assertEqual(s.digest(self.file), before)
        self.assertTrue(s.same_object(s.metadata(self.file), self.items[1]))

    def test_partial_failure_journal_catches_first_change(self):
        original = self.tx.set_mode

        def fail_on_file(item, mode):
            if not item['directory']:
                raise RuntimeError('simulated')
            original(item, mode)
        with patch.object(self.tx, 'set_mode', side_effect=fail_on_file):
            with self.assertRaises(RuntimeError):
                self.tx.apply()
        self.assertEqual(len(self.tx.operations), 1)
        result = self.tx.rollback()
        self.assertEqual(result['status'], 'ROLLED_BACK_CONTAINED')
        self.assertEqual(self.mode(self.data), 448)
        self.assertEqual(self.mode(self.file), 420)

    def test_no_chmod_when_initial_journal_fails(self):
        with patch.object(self.tx, 'save', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                self.tx.apply()
        self.assertEqual(self.mode(self.data), 511)
        self.assertEqual(self.mode(self.file), 420)

    def test_no_chmod_when_intent_persist_fails(self):
        original = self.tx.save

        def fail():
            if self.tx.operations:
                raise OSError('intent persistence')
            original()
        with patch.object(self.tx, 'save', side_effect=fail):
            with self.assertRaises(OSError):
                self.tx.apply()
        self.tx.rollback()
        self.assertEqual(self.mode(self.data), 511)

    def test_conservative_rollback_keeps_closed_directory(self):
        self.tx.apply()
        self.assertEqual(self.tx.rollback()['status'], 'ROLLED_BACK_CONTAINED')
        self.assertEqual(self.mode(self.data), 448)
        self.assertEqual(self.mode(self.file), 420)

    def recovery_policy(self):
        return {x['path']: dict(uid=x['uid'], gid=x['gid'], directory=x['directory'], modes=(x['mode'],)) for x in self.items}

    def test_interrupted_journal_can_recover_in_exact_scope(self):
        self.tx.apply()
        loaded = s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())
        result = loaded.rollback()
        self.assertEqual(result['status'], 'ROLLED_BACK_CONTAINED')
        self.assertEqual(self.mode(self.file), 420)
        self.assertEqual(self.mode(self.data), 448)

    def test_committed_journal_cannot_be_replayed(self):
        self.tx.apply()
        self.tx.commit()
        with self.assertRaisesRegex(s.Blocked, 'PHASE_NOT_INTERRUPTED'):
            s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())

    def test_recovery_rejects_expanded_scope(self):
        self.tx.apply()
        data = json.loads(self.tx.journal.read_text())
        data['items'][0]['path'] = '/outside/allowed/scope'
        self.tx.journal.write_text(json.dumps(data))
        with self.assertRaisesRegex(s.Blocked, 'SCOPE_DIFFERS'):
            s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())

    def test_recovery_rejects_unexpected_mode(self):
        self.tx.apply()
        data = json.loads(self.tx.journal.read_text())
        data['operations'][0]['after'] = 511
        self.tx.journal.write_text(json.dumps(data))
        with self.assertRaisesRegex(s.Blocked, 'MODE_INVALID'):
            s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())

    def test_recovery_rejects_public_journal(self):
        self.tx.apply()
        os.chmod(self.tx.journal, 420)
        with self.assertRaisesRegex(s.Blocked, 'JOURNAL_NOT_PRIVATE'):
            s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())

    def test_commit_requires_finished_apply(self):
        with self.assertRaisesRegex(s.Blocked, 'NOT_APPLIED'):
            self.tx.commit()

    def test_recovery_does_not_chmod_replaced_file(self):
        self.tx.apply()
        self.file.rename(self.data / 'previous')
        self.file.write_bytes(b'different object')
        os.chmod(self.file, 416)
        recovered = s.load_recovery(self.tx.journal, self.recovery_policy(), required_uid=os.geteuid())
        self.assertEqual(recovered.rollback()['status'], 'ROLLBACK_INCOMPLETE')
        self.assertEqual(self.mode(self.file), 416)

    def test_replaced_object_not_modified_by_rollback(self):
        self.tx.apply()
        old = self.data / 'old'
        self.file.rename(old)
        self.file.write_bytes(b'replacement')
        os.chmod(self.file, 416)
        result = self.tx.rollback()
        self.assertEqual(result['status'], 'ROLLBACK_INCOMPLETE')
        self.assertIn(str(self.file), result['pending_paths'])
        self.assertEqual(self.mode(self.file), 416)

    def test_symlink_refused(self):
        link = self.root / 'link'
        link.symlink_to(self.file)
        with self.assertRaises(s.Blocked):
            s.metadata(link)

    def test_hardlink_refused(self):
        os.link(self.file, self.root / 'hardlink')
        with self.assertRaises(s.Blocked):
            s.metadata(self.file)

    def test_metadata_change_before_apply_refused(self):
        os.chmod(self.file, 416)
        with self.assertRaises(s.Blocked):
            self.tx.apply()
        self.tx.rollback()
        self.assertEqual(self.mode(self.file), 416)

    def test_pre_change_guard_stops_without_mode_change(self):
        self.tx.pre_change = lambda: s.need(False, 'PANEL_CHANGED')
        with self.assertRaisesRegex(s.Blocked, 'PANEL_CHANGED'):
            self.tx.apply()
        self.assertEqual(self.mode(self.data), 511)
        self.assertFalse(self.tx.operations)

    def test_cron_every_quarter_hour(self):
        self.assertEqual(s.cron_next('*/15 * * * *', 'UTC', 0), 900)

    def test_cron_unknown_dialect_blocks(self):
        with self.assertRaises(s.Blocked):
            s.cron_next('0 */15 * * * *', 'UTC', 0)

    def test_cron_ambiguous_step_blocks(self):
        with self.assertRaises(s.Blocked):
            s.cron_next('5/10 * * * *', 'UTC', 0)
if __name__ == '__main__':
    unittest.main(verbosity=2)
