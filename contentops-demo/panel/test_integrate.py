import tempfile,unittest
from pathlib import Path
from integrate import prepare,prepare_directory,integrate,CSRF,LOGOUT
SOURCE="import hashlib\nclass App:\n    def get(self,x):return lambda f:f\napp=App()\ndef guard():\n"+CSRF+'\ndef logout():\n'+LOGOUT+'\ndef health():return None\n'
def docker(s):return "FROM python:3.13-slim\nCOPY <<'KYPH_APP' /app/app.py\n"+s+"\nKYPH_APP\nUSER 10001:10001\nCMD [\"gunicorn\",\"app:app\"]\n"
class IntegrateTests(unittest.TestCase):
 def test_repeated_update_is_idempotent_and_replaces_old_module(self):
  one=prepare(SOURCE,docker(SOURCE),'VERSION=1\n');self.assertEqual(one,prepare(one['app.py'],one['Dockerfile'],'VERSION=1\n'))
  new=prepare(one['app.py'],one['Dockerfile'],'VERSION=2\n');self.assertNotIn('VERSION=1',new['Dockerfile']);self.assertIn('VERSION=2',new['Dockerfile']);self.assertEqual(new['Dockerfile'].count("COPY <<'KYPH_CONTENTOPS_MODULE'"),1)
 def test_mismatched_source_rejected(self):
  with self.assertRaises(ValueError):prepare(SOURCE,docker(SOURCE+'#different'),'VERSION=1')
 def test_marker_cannot_bypass_guard_validation(self):
  broken=integrate(SOURCE).replace('if not identity or not identity(): abort(401)','pass')
  with self.assertRaises(ValueError):integrate(broken)
 def test_duplicate_block_or_changed_user_rejected(self):
  one=prepare(SOURCE,docker(SOURCE),'VERSION=1');extra="COPY <<'KYPH_CONTENTOPS_MODULE' /app/contentops.py\nVERSION=1\nKYPH_CONTENTOPS_MODULE\n"
  with self.assertRaises(ValueError):prepare(one['app.py'],one['Dockerfile']+extra,'VERSION=2')
  with self.assertRaises(ValueError):prepare(SOURCE,docker(SOURCE).replace('USER 10001:10001','USER 0'),'VERSION=1')
 def test_atomic_private_output_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);a=root/'app';d=root/'docker';m=root/'module';out=root/'ready';a.write_text(SOURCE);d.write_text(docker(SOURCE));m.write_text('VERSION=1')
   report=prepare_directory(a,d,out,m);self.assertFalse(report['live_source_verified']);self.assertFalse(report['backup_verified']);self.assertEqual(out.stat().st_mode&0o777,0o700);self.assertTrue(all(f.stat().st_mode&0o777==0o600 for f in out.iterdir()));before={f.name:f.read_bytes() for f in out.iterdir()}
   with self.assertRaises(ValueError):prepare_directory(a,d,out,m)
   self.assertEqual(before,{f.name:f.read_bytes() for f in out.iterdir()})
 def test_invalid_module_leaves_no_partial_output(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);a=root/'app';d=root/'docker';m=root/'module';out=root/'ready';a.write_text(SOURCE);d.write_text(docker(SOURCE));m.write_text('def invalid:')
   with self.assertRaises(SyntaxError):prepare_directory(a,d,out,m)
   self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(verbosity=2)
