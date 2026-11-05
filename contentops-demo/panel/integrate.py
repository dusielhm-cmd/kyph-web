"""Prepare reviewed private panel code. No live source access or deployment."""
import argparse,hashlib,json,os,tempfile
from pathlib import Path
CSRF="    if request.method == 'POST' and not valid_csrf(): abort(403)"
UPLOAD="    if request.path == '/contentops/archivos' and request.method == 'POST':\n        identity = app.extensions.get('contentops_identity')\n        if not identity or not identity(): abort(401)\n        request.max_content_length = 101 * 1024 * 1024\n"
LOGOUT="    session.clear()\n    return redirect('/login')\n\n@app.get('/healthz')"
REVOKE="    if session.get('co_sid') and os.environ.get('KYPH_CONTENTOPS','0')=='1':\n        with db() as con:\n            con.execute('DELETE FROM co_sessions WHERE token=?',(hashlib.sha256(session['co_sid'].encode()).hexdigest(),))\n"
MOUNT='# CONTENTOPS_MOUNT_V1\nfrom contentops import register_contentops\nregister_contentops(app, db, authenticated, csrf, DATA)'
USER='\nUSER 10001:10001'
def integrate(source):
 compile(source,'<private panel>','exec')
 if '# CONTENTOPS_MOUNT_V1' in source:
  if source.count(MOUNT)!=1 or source.count('# CONTENTOPS_MOUNT_V1')!=1 or source.count(UPLOAD+CSRF)!=1 or source.count(REVOKE+LOGOUT)!=1:raise ValueError('Mounted guards differ; review required')
  return source
 if source.count(CSRF)!=1 or source.count(LOGOUT)!=1:raise ValueError('Guard/logout differs; review required')
 return source.replace(CSRF,UPLOAD+CSRF).replace(LOGOUT,REVOKE+LOGOUT).rstrip()+'\n\n'+MOUNT+'\n'
def block(text,name,path):
 marker="COPY <<'"+name+"' "+path+'\n';ending='\n'+name+'\n'
 if text.count(marker)!=1 or text.count(ending)!=1:raise ValueError('Dockerfile heredoc differs; review required')
 a=text.index(marker)+len(marker);return a,text.index(ending,a)
def prepare(source,docker,module):
 compile(module,'<module>','exec');a,b=block(docker,'KYPH_APP','/app/app.py')
 if docker[a:b].strip()!=source.strip():raise ValueError('app.py and reviewed Dockerfile differ')
 if docker.count(USER)!=1:raise ValueError('Service user differs; review required')
 result=integrate(source);compile(result,'<integrated panel>','exec');docker=docker[:a]+result.rstrip()+docker[b:]
 if 'KYPH_CONTENTOPS_MODULE' in docker:
  a,b=block(docker,'KYPH_CONTENTOPS_MODULE','/app/contentops.py');docker=docker[:a]+module.rstrip()+docker[b:]
 else:docker=docker.replace(USER,"\nCOPY <<'KYPH_CONTENTOPS_MODULE' /app/contentops.py\n"+module.rstrip()+"\nKYPH_CONTENTOPS_MODULE\n"+USER,1)
 return {'app.py':result,'contentops.py':module,'Dockerfile':docker}
def prepare_directory(app_path,docker_path,output,module_path=None):
 app_path,docker_path,output=map(Path,(app_path,docker_path,output))
 if output.exists() or output.is_symlink():raise ValueError('Output exists; overwrite forbidden')
 if not output.parent.is_dir():raise ValueError('Output parent must exist')
 source,docker=app_path.read_text(),docker_path.read_text();module=Path(module_path or Path(__file__).with_name('contentops.py')).read_text();files=prepare(source,docker,module)
 sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
 report={'scope':'PREPARED_ONLY_NOT_DEPLOYED','live_source_verified':False,'backup_verified':False,'inputs_sha256':{'app.py':sha(source),'Dockerfile':sha(docker)},'outputs_sha256':{k:sha(v) for k,v in files.items()}}
 with tempfile.TemporaryDirectory(prefix='.kyph-integration-',dir=output.parent) as td:
  stage=Path(td)/'ready';stage.mkdir(mode=0o700)
  for name,content in {**files,'integration_report.json':json.dumps(report,indent=2)}.items():
   target=stage/name;target.write_text(content);os.chmod(target,0o600)
  stage.rename(output)
 return report
def main():
 p=argparse.ArgumentParser();p.add_argument('--app',type=Path,required=True);p.add_argument('--docker',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();prepare_directory(a.app,a.docker,a.output)
 print('Prepared private integration only. Live source, backup and Deploy remain unverified.')
if __name__=='__main__':main()
