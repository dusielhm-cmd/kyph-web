"""Private offline panel backup. Never stops services, deploys or overwrites data.
Backups contain secrets. Keep them private; never commit/upload their contents.
"""
import argparse,hashlib,json,os,shutil,sqlite3,tempfile
from pathlib import Path
from contextlib import closing
DB='auth.sqlite';MANIFEST='MANIFEST.json'
REQUIRED={'owner','sessions','co_users','co_scripts','co_versions','co_requests','co_approvals','co_audit'}
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def inventory(root):
 out={}
 for p in sorted(root.rglob('*')):
  if p.is_symlink():raise ValueError('Symlink rejected')
  if p.is_file():out[p.relative_to(root).as_posix()]=digest(p)
  elif not p.is_dir():raise ValueError('Unsupported file')
 return out
def check_db(p):
 with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)) as c:
  if c.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('SQLite integrity failed')
  names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
  if not REQUIRED<=names:raise ValueError('Incomplete panel/ContentOps schema')
  if c.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Foreign key check failed')
def copy_file(a,b):
 b.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(a,b);os.chmod(b,0o600)
def targets(a,b):
 a=Path(a).absolute();b=Path(b).absolute()
 if a.is_symlink() or not a.is_dir():raise ValueError('Invalid source')
 a=a.resolve();parent=b.parent.resolve()
 if b.exists() or b.is_symlink():raise ValueError('Overwrite forbidden')
 if parent==a or a in parent.parents:raise ValueError('Nested destination forbidden')
 if not parent.is_dir():raise ValueError('Missing destination parent')
 return a,parent/b.name
def validate(root):
 root=Path(root).absolute()
 if root.is_symlink() or not root.is_dir():raise ValueError('Invalid backup')
 before=inventory(root)
 if MANIFEST not in before:raise ValueError('Missing manifest')
 meta=json.loads((root/MANIFEST).read_text());expected=meta.get('files')
 if meta.get('format')!=1 or not isinstance(expected,dict):raise ValueError('Invalid manifest')
 if set(before)-{MANIFEST}!=set(expected):raise ValueError('Extra/missing files')
 for name,value in expected.items():
  rel=Path(name)
  if rel.is_absolute() or '..' in rel.parts or before[name]!=value:raise ValueError('Hash/path mismatch')
 if not {DB,'session.key'}<=expected.keys():raise ValueError('Incomplete backup')
 check_db(root/DB)
 if inventory(root)!=before:raise ValueError('Backup changed during validation')
 return {'status':'VERIFIED_BACKUP','files_verified':len(expected)}
def backup(source,dest,offline_confirmed=False):
 if not offline_confirmed:raise ValueError('Stop writes externally; offline confirmation required')
 source,dest=targets(source,dest);before={k:v for k,v in inventory(source).items() if k!=DB+'-shm'}
 if MANIFEST in before or not {DB,'session.key'}<=before.keys():raise ValueError('Invalid source volume')
 check_db(source/DB)
 with tempfile.TemporaryDirectory(prefix='.kyph-backup-',dir=dest.parent) as stage:
  root=Path(stage)/'payload';root.mkdir(mode=0o700)
  for name in before:
   if name not in {DB,DB+'-wal',DB+'-shm'}:copy_file(source/name,root/name)
  with closing(sqlite3.connect((source/DB).as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(root/DB)) as dst:
   src.backup(dst)
   dst.execute('PRAGMA journal_mode=DELETE')
  os.chmod(root/DB,0o600)
  if {k:v for k,v in inventory(source).items() if k!=DB+'-shm'}!=before:raise ValueError('Source changed; backup cancelled')
  (root/MANIFEST).write_text(json.dumps({'format':1,'files':inventory(root)},indent=2));os.chmod(root/MANIFEST,0o600)
  validate(root);root.rename(dest)
 return validate(dest)
def restore(source,dest):
 source,dest=targets(source,dest);validate(source);meta=json.loads((source/MANIFEST).read_text())
 with tempfile.TemporaryDirectory(prefix='.kyph-restore-',dir=dest.parent) as stage:
  root=Path(stage)/'payload';root.mkdir(mode=0o700)
  for name,value in meta['files'].items():
   copy_file(source/name,root/name)
   if digest(root/name)!=value:raise ValueError('Copy mismatch')
  check_db(root/DB)
  if inventory(root)!=meta['files']:raise ValueError('Restored set differs')
  root.rename(dest)
 return {'status':'RESTORED_TO_NEW_DIRECTORY','files_verified':len(meta['files'])}
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['backup','verify','restore']);p.add_argument('source',type=Path);p.add_argument('--destination',type=Path);p.add_argument('--offline-confirmed',action='store_true');a=p.parse_args()
 if a.action!='verify' and a.destination is None:p.error('--destination required')
 print(json.dumps(validate(a.source) if a.action=='verify' else backup(a.source,a.destination,a.offline_confirmed) if a.action=='backup' else restore(a.source,a.destination)))
if __name__=='__main__':main()
