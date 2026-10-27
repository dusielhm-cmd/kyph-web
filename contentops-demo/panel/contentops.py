"""ContentOps inside the existing panel, its cookie and its auth.sqlite volume.

No public registration, no provider calls and no publishing. Enable explicitly.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from flask import Blueprint, abort, jsonify, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = '''
CREATE TABLE IF NOT EXISTS co_users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1)));
CREATE TABLE IF NOT EXISTS co_sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_login_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until_time REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_scripts(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,front TEXT NOT NULL CHECK(front IN('01','02','03')),title TEXT NOT NULL,current_version INTEGER NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS co_versions(script_id TEXT NOT NULL,version INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,created_by TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(script_id,version));
CREATE TABLE IF NOT EXISTS co_requests(id TEXT PRIMARY KEY,script_id TEXT NOT NULL,base_version INTEGER NOT NULL,message TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_approvals(script_id TEXT NOT NULL,version INTEGER NOT NULL,digest TEXT NOT NULL,agent_id TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(script_id,version));
CREATE TABLE IF NOT EXISTS co_assets(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,script_id TEXT NOT NULL,version INTEGER NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,mime TEXT NOT NULL,bytes INTEGER NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_credits(job_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,delta REAL NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS co_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created_at REAL NOT NULL);
'''


def register_contentops(app, db, owner_authenticated, csrf, data_dir):
    if os.environ.get('KYPH_CONTENTOPS', '0') != '1':
        return
    with db() as con:
        con.executescript(SCHEMA)
    root = Path(data_dir) / 'contentops-files'
    root.mkdir(mode=0o700, exist_ok=True)
    bp = Blueprint('contentops', __name__, url_prefix='/contentops')
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method='scrypt')

    def sha(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def identity():
        if owner_authenticated():
            return {'id': 'OWNER', 'role': 'admin'}
        token = session.get('co_sid', '')
        if not token:
            return None
        with db() as con:
            row = con.execute('SELECT u.id FROM co_sessions s JOIN co_users u ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.active=1', (sha(token), time.time())).fetchone()
        return {'id': row['id'], 'role': 'agent'} if row else None

    app.extensions['contentops_identity'] = identity

    def protected(admin=False):
        def outer(fn):
            @wraps(fn)
            def inner(*args, **kwargs):
                who = identity()
                if not who:
                    abort(401)
                if admin and who['role'] != 'admin':
                    abort(403)
                return fn(who, *args, **kwargs)
            return inner
        return outer

    def log(con, who, action, target, detail=''):
        con.execute('INSERT INTO co_audit(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)', (who['id'], action, target, detail, time.time()))

    def begin(con):
        con.execute('BEGIN IMMEDIATE')

    def owned_script(con, who, sid):
        row = con.execute('SELECT * FROM co_scripts WHERE id=?', (sid,)).fetchone()
        if not row or (who['role'] != 'admin' and row['agent_id'] != who['id']):
            abort(404)
        return row

    def text(name, maximum=20000):
        value = request.form.get(name, '').strip()
        if not value or len(value) > maximum:
            abort(400)
        return value

    def version():
        try:
            return int(request.form.get('version', ''))
        except (ValueError, TypeError):
            abort(400)

    def render(body, **values):
        # Inherits the panel's CSP: server-rendered forms only, no client role switch.
        return render_template_string('''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KYPH ContentOps</title><style>body{font:16px system-ui;background:#f4f7fd;color:#152242;margin:0}main{max-width:1000px;margin:auto;padding:28px}header{color:#0d286e;font-weight:800;font-size:24px}nav{display:flex;gap:18px;flex-wrap:wrap;margin:24px 0}a{color:#164ccc}.card{background:white;border:1px solid #dde5f4;border-radius:16px;padding:24px;margin:18px 0}label{display:block;margin:16px 0 8px}input,textarea,select{box-sizing:border-box;width:100%;padding:12px;font:inherit}button{background:#164ccc;color:white;border:0;border-radius:8px;padding:13px 20px;margin-top:12px;font:inherit}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}.muted{color:#58677c}h1{font-size:32px}.error{color:#9c2636}</style><main><header>KYPH ContentOps</header><nav><a href="/contentops/">Mis guiones</a><a href="/contentops/archivos">Videos y portadas</a><a href="/contentops/creditos">Mis créditos</a></nav>''' + body + '''</main></html>''', csrf=csrf(), **values)

    @bp.route('/login', methods=['GET', 'POST'])
    def login():
        if identity():
            return redirect('/contentops/')
        error = ''
        status = 200
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()[:254]
            now = time.time()
            # Per-account and global buckets. Do not trust client proxy headers as IP.
            keys = ['global', sha(email)]
            with db() as con:
                begin(con)
                limits = [con.execute('SELECT * FROM co_login_limits WHERE key=?', (key,)).fetchone() for key in keys]
                if any(row and row['until_time'] > now for row in limits):
                    abort(429)
                user = con.execute('SELECT * FROM co_users WHERE email=? AND active=1', (email,)).fetchone()
                supplied = request.form.get('password', '')[:128]
                correct = check_password_hash(user['password'] if user else dummy_hash, supplied)
                if not user or not correct:
                    for key, row in zip(keys, limits):
                        count = (row['count'] if row and row['until_time'] == 0 else 0) + 1
                        threshold = 50 if key == 'global' else 5
                        con.execute('INSERT OR REPLACE INTO co_login_limits VALUES(?,?,?)', (key, count, now + 900 if count >= threshold else 0))
                    error, status = 'No fue posible iniciar sesión con esos datos.', 401
                else:
                    token = secrets.token_urlsafe(48)
                    con.execute('DELETE FROM co_sessions WHERE expires<=?', (now,))
                    con.execute('INSERT INTO co_sessions VALUES(?,?,?)', (sha(token), user['id'], now + 7200))
                    con.execute('DELETE FROM co_login_limits WHERE key=?', (sha(email),))
                    log(con, {'id': user['id']}, 'LOGIN', user['id'])
                    session.clear()
                    session.permanent = True
                    session['co_sid'] = token
                    return redirect('/contentops/')
        return render('''<section class="card"><h1>Acceso de agentes</h1><p>Usa tu acceso individual habilitado por KYPH.</p><p class="error">{{error}}</p><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Correo<input name="email" type="email" autocomplete="username" required></label><label>Contraseña<input name="password" type="password" autocomplete="current-password" maxlength="128" required></label><button>Entrar</button></form><p><a href="/login">Acceso de David</a></p></section>''', error=error), status

    @bp.post('/logout')
    @protected()
    def logout(who):
        with db() as con:
            con.execute('DELETE FROM co_sessions WHERE token=?', (sha(session.get('co_sid', '')),))
            if who['role'] == 'admin':
                con.execute('DELETE FROM sessions WHERE token=?', (session.get('sid', ''),))
        session.clear()
        return redirect('/contentops/login')

    @bp.get('/')
    @protected()
    def home(who):
        with db() as con:
            rows = con.execute('SELECT * FROM co_scripts ORDER BY title' if who['role'] == 'admin' else 'SELECT * FROM co_scripts WHERE agent_id=? ORDER BY title', () if who['role'] == 'admin' else (who['id'],)).fetchall()
        return render('''<h1>Mis guiones</h1><p>Revisa tu versión, pide cambios y aprueba antes de grabar.</p>{% if admin %}<p><a href="/contentops/admin">Administrar guiones y accesos</a></p>{% endif %}{% for s in scripts %}<section class="card"><h2><a href="/contentops/guiones/{{s.id}}">{{s.title}}</a></h2><p>Frente {{s.front}} · V{{s.current_version}} · {{s.state}}</p></section>{% else %}<p>Todavía no hay guiones asignados.</p>{% endfor %}<form action="/contentops/logout" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><button>Cerrar sesión</button></form>''', scripts=rows, admin=who['role']=='admin')

    @bp.get('/admin')
    @protected(admin=True)
    def admin(who):
        with db() as con:
            users = con.execute('SELECT id,email,active FROM co_users ORDER BY email').fetchall()
        return render('''<h1>Guiones y accesos</h1><p>No hay registro público ni envío de invitaciones.</p><section class="card"><h2>Habilitar acceso autorizado</h2><form action="/contentops/admin/agentes" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Correo del agente<input name="email" type="email" required></label><label>Contraseña inicial privada<input name="password" type="password" minlength="14" maxlength="128" autocomplete="new-password" required></label><button>Crear acceso</button></form></section><section class="card"><h2>Asignar guion V1</h2><form action="/contentops/admin/guiones" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Agente<select name="agent_id">{% for u in users if u.active %}<option value="{{u.id}}">{{u.email}}</option>{% endfor %}</select></label><label>Frente<select name="front"><option value="01">01 · M40 y pensiones</option><option value="02">02 · Seguros y PPR</option><option value="03">03 · Reclutamiento</option></select></label><label>Título<input name="title" maxlength="180" required></label><label>Guion<textarea name="body" rows="8" maxlength="20000" required></textarea></label><button>Guardar V1</button></form></section>{% for u in users %}<section class="card"><strong>{{u.email}}</strong><p>{{'Activo' if u.active else 'Baja'}}</p>{% if u.active %}<form action="/contentops/admin/agentes/{{u.id}}/baja" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><button>Desactivar acceso y sesiones</button></form>{% endif %}</section>{% endfor %}''', users=users)

    @bp.post('/admin/agentes')
    @protected(admin=True)
    def create_agent(who):
        email = text('email', 254).lower()
        password = text('password', 128)
        if '@' not in email or len(password) < 14:
            abort(400)
        uid = secrets.token_hex(16)
        with db() as con:
            begin(con)
            try:
                con.execute('INSERT INTO co_users VALUES(?,?,?,1)', (uid, email, generate_password_hash(password, method='scrypt')))
            except sqlite3.IntegrityError:
                abort(409)
            log(con, who, 'AGENT_CREATED', uid)
        return jsonify(id=uid), 201

    @bp.post('/admin/agentes/<uid>/baja')
    @protected(admin=True)
    def disable_agent(who, uid):
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=?', (uid,)).fetchone():
                abort(404)
            con.execute('UPDATE co_users SET active=0 WHERE id=?', (uid,))
            con.execute('DELETE FROM co_sessions WHERE user_id=?', (uid,))
            log(con, who, 'AGENT_DISABLED', uid)
        return jsonify(ok=True)

    @bp.post('/admin/guiones')
    @protected(admin=True)
    def create_script(who):
        agent, front, title, body = text('agent_id', 64), text('front', 2), text('title', 180), text('body')
        if front not in ('01', '02', '03'):
            abort(400)
        sid = secrets.token_hex(16)
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=? AND active=1', (agent,)).fetchone():
                abort(404)
            con.execute('INSERT INTO co_scripts VALUES(?,?,?,?,1,?)', (sid, agent, front, title, 'PENDIENTE_APROBACION'))
            con.execute('INSERT INTO co_versions VALUES(?,1,?,?,?,?)', (sid, body, sha(body), who['id'], time.time()))
            log(con, who, 'V1_CREATED', sid)
        return jsonify(id=sid, version=1), 201

    @bp.get('/guiones/<sid>')
    @protected()
    def script(who, sid):
        with db() as con:
            row = owned_script(con, who, sid)
            versions = con.execute('SELECT version,body,digest FROM co_versions WHERE script_id=? ORDER BY version', (sid,)).fetchall()
            pending = con.execute('SELECT * FROM co_requests WHERE script_id=? AND state=? ORDER BY created_at', (sid, 'PENDIENTE')).fetchall()
            approvals = con.execute('SELECT version,digest,created_at FROM co_approvals WHERE script_id=? ORDER BY version', (sid,)).fetchall()
        if request.args.get('format') == 'json':
            return jsonify(id=row['id'], front=row['front'], state=row['state'], current_version=row['current_version'], versions=[dict(v) for v in versions], requests=[dict(v) for v in pending], approvals=[dict(v) for v in approvals])
        return render('''<h1>{{s.title}}</h1><p>Frente {{s.front}} · V{{s.current_version}} · {{s.state}}</p>{% for v in versions %}<section class="card"><h2>V{{v.version}}</h2><pre>{{v.body}}</pre></section>{% endfor %}{% for r in pending %}<section class="card"><h2>Cambio solicitado</h2><pre>{{r.message}}</pre></section>{% endfor %}{% if admin %}<section class="card"><h2>Preparar nueva versión</h2><form action="/contentops/admin/guiones/{{s.id}}/version" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><label>Guion editable<textarea name="body" rows="10" maxlength="20000" required>{{versions[-1].body}}</textarea></label><button>Guardar versión para revisión</button></form></section>{% elif s.state != 'APROBADO' %}<section class="card"><form action="/contentops/guiones/{{s.id}}/cambios" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><input type="hidden" name="request_id" value="{{nonce}}"><label>¿Qué quieres cambiar?<textarea name="message" maxlength="5000" required></textarea></label><button>Solicitar cambios</button></form>{% if s.state=='PENDIENTE_APROBACION' %}<form action="/contentops/guiones/{{s.id}}/aprobar" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="version" value="{{s.current_version}}"><input type="hidden" name="digest" value="{{versions[-1].digest}}"><label><input type="checkbox" name="confirm" value="yes" required>Apruebo este guion V{{s.current_version}} para grabar</label><button>Aprobar esta versión</button></form>{% endif %}</section>{% else %}<p>Aprobación guardada. Esta aprobación permite grabar; no autoriza publicación.</p>{% endif %}''', s=row, versions=versions, pending=pending, admin=who['role']=='admin', nonce=secrets.token_hex(24))

    @bp.post('/guiones/<sid>/cambios')
    @protected()
    def changes(who, sid):
        if who['role'] != 'agent':
            abort(403)
        base, message, rid = version(), text('message', 5000), text('request_id', 64)
        if len(rid) < 24:
            abort(400)
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            existing = con.execute('SELECT * FROM co_requests WHERE id=?', (rid,)).fetchone()
            if existing:
                if existing['script_id'] == sid and existing['base_version'] == base and existing['message'] == message:
                    return redirect('/contentops/guiones/' + sid)
                abort(409)
            if row['current_version'] != base or row['state'] == 'APROBADO':
                abort(409)
            if con.execute('SELECT 1 FROM co_requests WHERE script_id=? AND state=?', (sid, 'PENDIENTE')).fetchone():
                abort(409)
            con.execute('INSERT INTO co_requests VALUES(?,?,?,?,?,?)', (rid, sid, base, message, 'PENDIENTE', time.time()))
            con.execute('UPDATE co_scripts SET state=? WHERE id=?', ('CAMBIOS_SOLICITADOS', sid))
            log(con, who, 'CHANGES_REQUESTED', sid, rid)
        return redirect('/contentops/guiones/' + sid)

    @bp.post('/admin/guiones/<sid>/version')
    @protected(admin=True)
    def save_version(who, sid):
        base, body = version(), text('body')
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            if row['current_version'] != base or row['state'] != 'CAMBIOS_SOLICITADOS':
                abort(409)
            con.execute('INSERT INTO co_versions VALUES(?,?,?,?,?,?)', (sid, base+1, body, sha(body), who['id'], time.time()))
            con.execute('UPDATE co_requests SET state=? WHERE script_id=? AND state=?', ('RESUELTA', sid, 'PENDIENTE'))
            con.execute('UPDATE co_scripts SET current_version=?,state=? WHERE id=?', (base+1, 'PENDIENTE_APROBACION', sid))
            log(con, who, 'VERSION_CREATED', sid, str(base+1))
        return redirect('/contentops/guiones/' + sid)

    @bp.post('/guiones/<sid>/aprobar')
    @protected()
    def approve(who, sid):
        if who['role'] != 'agent' or request.form.get('confirm') != 'yes':
            abort(403)
        base, digest = version(), text('digest', 64)
        with db() as con:
            begin(con)
            row = owned_script(con, who, sid)
            v = con.execute('SELECT digest FROM co_versions WHERE script_id=? AND version=?', (sid, base)).fetchone()
            if row['current_version'] != base or not v or not hmac.compare_digest(v['digest'], digest):
                abort(409)
            if row['state'] == 'APROBADO':
                return redirect('/contentops/guiones/' + sid)
            if row['state'] != 'PENDIENTE_APROBACION':
                abort(409)
            con.execute('INSERT INTO co_approvals VALUES(?,?,?,?,?)', (sid, base, digest, who['id'], time.time()))
            con.execute('UPDATE co_scripts SET state=? WHERE id=?', ('APROBADO', sid))
            log(con, who, 'VERSION_APPROVED', sid, str(base))
        return redirect('/contentops/guiones/' + sid)

    @bp.get('/creditos')
    @protected()
    def credits(who):
        with db() as con:
            rows = con.execute('SELECT job_id,delta,kind,source FROM co_credits WHERE agent_id=? ORDER BY created_at', (who['id'],)).fetchall()
        return render('''<h1>Mis créditos</h1><section class="card"><p>Saldo: <strong>NO CONCILIADO</strong></p><p>No hay una bolsa independiente de Descript por agente. Solo se mostrarán consumos atribuibles y verificados, sin descontar simulaciones.</p>{% for r in rows %}<p>{{r.job_id}} · {{r.delta}} · {{r.kind}} · {{r.source}}</p>{% endfor %}<p>No se ejecutan ediciones ni recargas desde esta pantalla.</p></section>''', rows=rows)

    @bp.post('/admin/consumos')
    @protected(admin=True)
    def record_usage(who):
        import math
        job, uid, source = text('job_id', 180), text('agent_id', 64), text('source', 2000)
        try:
            used = float(request.form.get('credits', ''))
        except ValueError:
            abort(400)
        if not math.isfinite(used) or used <= 0 or used > 100000 or request.form.get('verified') != 'yes':
            abort(400)
        with db() as con:
            begin(con)
            if not con.execute('SELECT id FROM co_users WHERE id=?', (uid,)).fetchone():
                abort(404)
            old = con.execute('SELECT * FROM co_credits WHERE job_id=?', (job,)).fetchone()
            if old:
                if old['agent_id'] == uid and old['delta'] == -used and old['source'] == source:
                    return jsonify(ok=True, repeated=True)
                abort(409)
            con.execute('INSERT INTO co_credits VALUES(?,?,?,?,?,?)', (job, uid, -used, 'USO_VERIFICADO_MANUAL', source, time.time()))
            log(con, who, 'USAGE_RECORDED', uid, job)
        return jsonify(ok=True), 201

    @bp.get('/archivos')
    @protected()
    def assets(who):
        with db() as con:
            rows = con.execute('SELECT id,name,kind,state,bytes FROM co_assets ORDER BY created_at' if who['role']=='admin' else 'SELECT id,name,kind,state,bytes FROM co_assets WHERE agent_id=? ORDER BY created_at', () if who['role']=='admin' else (who['id'],)).fetchall()
            scripts = con.execute('SELECT id,title,current_version FROM co_scripts WHERE state=?' + ('' if who['role']=='admin' else ' AND agent_id=?'), ('APROBADO',) if who['role']=='admin' else ('APROBADO',who['id'])).fetchall()
        enabled = os.environ.get('KYPH_CONTENTOPS_UPLOADS', '0') == '1'
        return render('''<h1>Videos y portadas</h1><p>Originales privados. No se comparten con otros agentes ni se envían a Descript.</p>{% for r in rows %}<section class="card"><strong>{{r.name}}</strong><p>{{r.kind}} · {{r.bytes}} bytes · {{r.state}}</p></section>{% endfor %}{% if enabled and scripts %}<section class="card"><form action="/contentops/archivos" method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{csrf}}"><label>Guion aprobado<select name="script_id">{% for s in scripts %}<option value="{{s.id}}">{{s.title}} · V{{s.current_version}}</option>{% endfor %}</select></label><label>Versión aprobada<input type="number" name="version" min="1" required></label><label>Tipo<select name="kind"><option value="video">Video original</option><option value="cover">Portada</option></select></label><label>Archivo<input type="file" name="file" accept="video/mp4,video/x-matroska,image/png,image/jpeg" required></label><label><input type="checkbox" name="consent" value="yes" required>Autorizo almacenamiento privado para mi revisión. Declaro tener los derechos del archivo.</label><button>Guardar para revisión privada</button></form></section>{% elif enabled %}<p>Primero aprueba un guion para poder cargar su video o portada.</p>{% else %}<p>Carga deshabilitada hasta verificar volumen privado, capacidad y respaldo.</p>{% endif %}''', rows=rows, enabled=enabled, scripts=scripts)

    @bp.post('/archivos')
    @protected()
    def upload(who):
        if os.environ.get('KYPH_CONTENTOPS_UPLOADS', '0') != '1':
            abort(404)
        if request.form.get('consent') != 'yes':
            abort(400)
        f = request.files.get('file')
        kind = request.form.get('kind')
        if not f or kind not in ('video', 'cover'):
            abort(400)
        sid, base = text('script_id',64), version()
        uid = secrets.token_hex(24)
        path = root / uid
        count, digest, head = 0, hashlib.sha256(), b''
        try:
            with db() as con:
                begin(con)
                script = owned_script(con,who,sid)
                if script['state']!='APROBADO' or script['current_version']!=base or not con.execute('SELECT 1 FROM co_approvals WHERE script_id=? AND version=? AND agent_id=?',(sid,base,script['agent_id'])).fetchone():
                    abort(409)
                agent_id=script['agent_id']
                used = con.execute('SELECT COALESCE(SUM(bytes),0) AS n FROM co_assets WHERE agent_id=?', (agent_id,)).fetchone()['n']
                with path.open('xb') as out:
                    os.chmod(path, 0o600)
                    while chunk := f.stream.read(65536):
                        head = (head + chunk)[:16]
                        count += len(chunk)
                        if count > 100*1024*1024 or used + count > 500*1024*1024:
                            abort(413)
                        digest.update(chunk)
                        out.write(chunk)
                video = len(head) >= 12 and (head[4:8] == b'ftyp' or head[:4] == b'\x1aE\xdf\xa3')
                picture = head.startswith(b'\x89PNG\r\n\x1a\n') or head.startswith(b'\xff\xd8\xff')
                if not count or not (video if kind == 'video' else picture):
                    abort(415)
                mime = 'application/octet-stream'
                name = Path(f.filename or 'archivo').name[:180]
                con.execute('INSERT INTO co_assets VALUES(?,?,?,?,?,?,?,?,?,?,?)', (uid, agent_id, sid, base, kind, name, mime, count, digest.hexdigest(), 'CUARENTENA', time.time()))
                log(con, who, 'PRIVATE_UPLOAD', uid, json.dumps({'consent': 'private_review_v1', 'sha256': digest.hexdigest()}))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        # No inline download, playback, public URL, provider submission or acceptance of
        # file safety. Magic bytes are preliminary only; inspection remains pending.
        return redirect('/contentops/archivos')

    app.register_blueprint(bp)
