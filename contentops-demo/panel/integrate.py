"""Patch the recovered/private panel source without putting that source in Git.

Run against a reviewed copy, not a running service or its /data volume.
"""
import argparse
import shutil
from pathlib import Path


def integrate(source):
    if '# CONTENTOPS_MOUNT_V1' in source:
        return source
    old = "    if request.method == 'POST' and not valid_csrf(): abort(403)"
    if source.count(old) != 1:
        raise ValueError('Existing guard differs: review current source before integrating')
    source = source.replace(old, "    if request.path == '/contentops/archivos' and request.method == 'POST':\n        identity = app.extensions.get('contentops_identity')\n        if not identity or not identity(): abort(401)\n        request.max_content_length = 101 * 1024 * 1024\n" + old)
    old = "    session.clear()\n    return redirect('/login')\n\n@app.get('/healthz')"
    if source.count(old) != 1:
        raise ValueError('Existing logout differs: review current source before integrating')
    source = source.replace(old, "    if session.get('co_sid') and os.environ.get('KYPH_CONTENTOPS','0')=='1':\n        with db() as con:\n            con.execute('DELETE FROM co_sessions WHERE token=?',(hashlib.sha256(session['co_sid'].encode()).hexdigest(),))\n" + old)
    source += "\n# CONTENTOPS_MOUNT_V1\nfrom contentops import register_contentops\nregister_contentops(app, db, authenticated, csrf, DATA)\n"
    return source


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--app',type=Path,required=True)
    parser.add_argument('--docker',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    source=args.app.read_text()
    docker=args.docker.read_text()
    marker="COPY <<'KYPH_APP' /app/app.py\n"
    if docker.count(marker)!=1 or docker.count('\nKYPH_APP\n')!=1:
        raise ValueError('Existing Dockerfile differs: no automatic replacement')
    start=docker.index(marker)+len(marker)
    end=docker.index('\nKYPH_APP\n',start)
    if docker[start:end].strip()!=source.strip():
        raise ValueError('app.py and current Dockerfile do not match')
    result=integrate(source)
    module=Path(__file__).with_name('contentops.py').read_text()
    docker=docker[:start]+result.rstrip()+docker[end:]
    docker=docker.replace('\nUSER 10001:10001', "\nCOPY <<'KYPH_CONTENTOPS_MODULE' /app/contentops.py\n"+module.rstrip()+"\nKYPH_CONTENTOPS_MODULE\nUSER 10001:10001",1)
    args.output.mkdir(parents=True,exist_ok=True)
    for name,content in [('app.py',result),('contentops.py',module),('Dockerfile',docker)]:
        target=args.output/name
        if target.exists():
            raise ValueError('Output already exists; preserve it and choose a new directory')
        target.write_text(content)
    print('Prepared same-service integration. No Deploy, schema update on live server or network calls.')


if __name__=='__main__':
    main()
