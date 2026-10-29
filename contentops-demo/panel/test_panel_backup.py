import importlib.util,os,pathlib,secrets,sqlite3,tempfile,unittest
from panel_backup import backup,restore,validate
PREP=pathlib.Path(os.environ.get('KYPH_PANEL_SOURCE',str(pathlib.Path(__file__).resolve().parent)))
class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.data=self.root/'data';self.data.mkdir()
  os.environ.update(DATA_DIR=str(self.data),PANEL_HOST='panel.test',KYPH_CONTENTOPS='1',KYPH_CONTENTOPS_UPLOADS='0')
  spec=importlib.util.spec_from_file_location('recovery_'+secrets.token_hex(4),PREP/'app.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with m.db() as c:
   c.execute("INSERT INTO co_users VALUES('A','demo@example.invalid','not-real',1)")
   c.execute("INSERT INTO co_scripts VALUES('S','A','02','Guion',2,'APROBADO')")
   c.execute("INSERT INTO co_versions VALUES('S',1,'V1','H1','OWNER',1)")
   c.execute("INSERT INTO co_versions VALUES('S',2,'V2','H2','OWNER',2)")
   c.execute("INSERT INTO co_requests VALUES('R','S',1,'Cambiar inicio','RESUELTA',1.5)")
   c.execute("INSERT INTO co_approvals VALUES('S',2,'H2','A',3)")
  (self.data/'sheets-reader.json').write_text('{"fixture":true}')
  (self.data/'contentops-files'/'synthetic').write_bytes(b'private-test-file')
 def tearDown(self):self.tmp.cleanup()
 def snapshot(self,root):
  with sqlite3.connect(root/'auth.sqlite') as c:return {t:c.execute('SELECT * FROM '+t+' ORDER BY 1').fetchall() for t in ['co_users','co_scripts','co_versions','co_requests','co_approvals']}
 def test_roundtrip_preserves_versions_approval_key_and_files(self):
  original=self.snapshot(self.data);out=self.root/'backup';rest=self.root/'restored';backup(self.data,out,True);restore(out,rest)
  self.assertEqual(original,self.snapshot(rest))
  for f in ['session.key','sheets-reader.json','contentops-files/synthetic']:
   self.assertEqual((self.data/f).read_bytes(),(rest/f).read_bytes());self.assertEqual((rest/f).stat().st_mode&0o777,0o600)
  self.assertEqual(rest.stat().st_mode&0o777,0o700)
 def test_tamper_missing_extra_and_overwrite_rejected(self):
  out=self.root/'backup';backup(self.data,out,True)
  with self.assertRaises(ValueError):restore(out,self.data)
  asset=out/'contentops-files/synthetic';asset.write_bytes(b'changed')
  with self.assertRaises(ValueError):validate(out)
  asset.write_bytes(b'private-test-file');(out/'extra').write_text('extra')
  with self.assertRaises(ValueError):restore(out,self.root/'restored')
  self.assertFalse((self.root/'restored').exists());(out/'extra').unlink();asset.unlink()
  with self.assertRaises(ValueError):validate(out)
 def test_offline_links_nested_paths_rejected(self):
  with self.assertRaises(ValueError):backup(self.data,self.root/'backup')
  with self.assertRaises(ValueError):backup(self.data,self.data/'backup',True)
  (self.data/'link').symlink_to('/etc/hostname')
  with self.assertRaises(ValueError):backup(self.data,self.root/'backup',True)
 def test_committed_wal_rows_restored(self):
  c=sqlite3.connect(self.data/'auth.sqlite');c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA wal_autocheckpoint=0');c.execute("UPDATE co_versions SET body='V2 WAL' WHERE version=2");c.commit()
  try:
   self.assertTrue((self.data/'auth.sqlite-wal').exists());out=self.root/'backup';backup(self.data,out,True);restore(out,self.root/'restored');self.assertEqual(self.snapshot(self.data),self.snapshot(self.root/'restored'))
  finally:c.close()
if __name__=='__main__':unittest.main(verbosity=2)
